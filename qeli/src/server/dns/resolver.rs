//! Portable DNS resolver engine, shared by UDP/TCP listeners and host unit tests.

use crate::config::server::DnsConfig;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Per-profile cache. Boxed slices retain exactly their length, so the packet-byte
/// accounting includes both normalised queries and responses without hidden Vec capacity.
/// Entry metadata and in-flight network buffers are outside this payload budget.
#[derive(Default)]
pub struct DnsCacheStore {
    entries: HashMap<Box<[u8]>, CachedResponse>,
    payload_bytes: usize,
}

// Response payload, insertion time, and its record-derived lifetime.
type CachedResponse = (Box<[u8]>, Instant, Duration);

pub type DnsCache = Arc<RwLock<DnsCacheStore>>;

pub(crate) fn new_cache() -> DnsCache {
    Arc::new(RwLock::new(DnsCacheStore::default()))
}

const MAX_CACHE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub type DnsBlocklist = Arc<HashSet<String>>;

/// Ceiling on a record-derived cache lifetime. Short authoritative TTLs are honoured exactly;
/// raising 1..4 seconds to a local floor serves records beyond the lifetime chosen by the zone.
const MAX_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Walk a compressed DNS name once for both framing and blocklist decoding.
/// Return the end of its on-wire representation, but validate the entire expanded name.
/// Pointers refer backwards to names, never into the header; labels and pointer chains
/// have bounded work and the expanded name includes its terminating root in the 255 limit.
fn walk_name<'a>(msg: &'a [u8], mut pos: usize, mut label: impl FnMut(&'a [u8])) -> Option<usize> {
    let mut end = None;
    let mut wire_len = 1usize;
    // A 255-byte name may have 127 labels. Compression adds hops but no expanded
    // bytes, so a 128-step total would reject its otherwise valid compressed form.
    for _ in 0..256 {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            let low = *msg.get(pos.checked_add(1)?)?;
            let target = (((len & 0x3F) as usize) << 8) | low as usize;
            if target < 12 || target >= pos {
                return None;
            }
            end.get_or_insert(pos.checked_add(2)?);
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            return end.or_else(|| pos.checked_add(1));
        }
        wire_len = wire_len.checked_add(1 + usize::from(len))?;
        if wire_len > 255 {
            return None;
        }
        let start = pos.checked_add(1)?;
        pos = start
            .checked_add(usize::from(len))
            .filter(|end| *end <= msg.len())?;
        label(&msg[start..pos]);
    }
    None
}

fn skip_name(msg: &[u8], pos: usize) -> Option<usize> {
    walk_name(msg, pos, |_| {})
}

/// Bounded RR walk used by framing, RDATA, TTL and EDNS policy. Unknown RDATA
/// remains opaque; offsets never change while a message is being examined.
struct DnsRecord {
    section: usize, // 0=ANSWER, 1=AUTHORITY, 2=ADDITIONAL
    start: usize,
    data: usize,
    end: usize,
    rtype: u16,
    class: u16,
    ttl: u32,
}

fn walk_records(msg: &[u8], mut visit: impl FnMut(DnsRecord) -> Option<()>) -> Option<()> {
    let mut pos = question_section_end(msg)?;
    for (section, offset) in [6, 8, 10].into_iter().enumerate() {
        let count = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        for _ in 0..count {
            let header = skip_name(msg, pos)?;
            let data = header.checked_add(10).filter(|end| *end <= msg.len())?;
            let len = usize::from(u16::from_be_bytes([msg[header + 8], msg[header + 9]]));
            let end = data.checked_add(len).filter(|end| *end <= msg.len())?;
            visit(DnsRecord {
                section,
                start: pos,
                data,
                end,
                rtype: u16::from_be_bytes([msg[header], msg[header + 1]]),
                class: u16::from_be_bytes([msg[header + 2], msg[header + 3]]),
                ttl: u32::from_be_bytes([
                    msg[header + 4],
                    msg[header + 5],
                    msg[header + 6],
                    msg[header + 7],
                ]),
            })?;
            pos = end;
        }
    }
    (pos == msg.len()).then_some(()) // No unframed bytes after the counted sections.
}

/// Validate common RDATA without rewriting it. Unknown types and class-specific
/// formats remain transparent (RFC 3597); this is not full DNSSEC/RRset validation.
fn validate_record_data(msg: &[u8], rr: &DnsRecord) -> Option<()> {
    let len = rr.end - rr.data;
    let name_end = |start| skip_name(msg, start).filter(|end| *end <= rr.end);
    let valid = match (rr.rtype, rr.class) {
        (1, 1) => len == 4, // IN A; other classes can use a different wire format.
        (28, 1) => len == 16,
        (2 | 5 | 12 | 39, _) => name_end(rr.data) == Some(rr.end), // NS/CNAME/PTR/DNAME
        (15, _) => len >= 3 && name_end(rr.data + 2) == Some(rr.end), // MX
        (33, 1) => len >= 7 && name_end(rr.data + 6) == Some(rr.end), // SRV
        (6, _) => {
            let rname = name_end(rr.data)?;
            let numeric = name_end(rname)?;
            numeric.checked_add(20) == Some(rr.end)
        }
        (16, _) => {
            let mut pos = rr.data;
            while pos < rr.end {
                pos = pos.checked_add(1 + usize::from(msg[pos]))?;
                if pos > rr.end {
                    return None;
                }
            }
            len != 0 // One or more character strings; a zero-length string is legal.
        }
        _ => true,
    };
    valid.then_some(())
}

fn dns_message_is_complete(msg: &[u8]) -> bool {
    walk_records(msg, |rr| validate_record_data(msg, &rr)).is_some()
}

/// RFC 2181 section 8: the high TTL bit means zero, not an enormous lifetime.
fn effective_ttl(value: u32) -> u32 {
    if value & 0x8000_0000 != 0 {
        0
    } else {
        value
    }
}

/// Subtract `age` seconds from every resource record's TTL, in place, saturating at zero.
///
/// Walks ANSWER + AUTHORITY + ADDITIONAL, because all three carry cacheable records and a stub
/// resolver honours the TTLs it sees in each. The OPT pseudo-record (type 41) is SKIPPED: its
/// TTL field is not a lifetime at all but the extended RCODE and EDNS flags, so decrementing it
/// would corrupt the answer's error code and DO bit rather than age anything.
///
/// A malformed message stops the walk where it stops — the records already adjusted stay
/// adjusted, which is strictly better than serving the whole thing with stale lifetimes, and no
/// index is ever written without having been bounds-checked first.
fn decrement_ttls(msg: &mut [u8], age: u32) {
    if age == 0 || msg.len() < 12 {
        return;
    }
    let counts = [
        u16::from_be_bytes([msg[6], msg[7]]) as usize, // ANCOUNT
        u16::from_be_bytes([msg[8], msg[9]]) as usize, // NSCOUNT
        u16::from_be_bytes([msg[10], msg[11]]) as usize, // ARCOUNT
    ];
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = match skip_name(msg, pos).and_then(|p| p.checked_add(4)) {
            Some(p) => p,
            None => return,
        };
    }
    for count in counts {
        for _ in 0..count {
            let after_name = match skip_name(msg, pos) {
                Some(p) => p,
                None => return,
            };
            if after_name + 10 > msg.len() {
                return;
            }
            let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
            let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
            let Some(record_end) = after_name
                .checked_add(10)
                .and_then(|header_end| header_end.checked_add(rdlen))
                .filter(|end| *end <= msg.len())
            else {
                return;
            };
            if rtype != 41 {
                let t = after_name + 4;
                let ttl = u32::from_be_bytes([msg[t], msg[t + 1], msg[t + 2], msg[t + 3]]);
                msg[t..t + 4]
                    .copy_from_slice(&effective_ttl(ttl).saturating_sub(age).to_be_bytes());
            }
            pos = record_end;
        }
    }
}

/// A whole-message cache must expire when ANY replayed RR expires, including
/// authority and glue. OPT's pseudo-TTL is metadata and never contributes.
fn record_min_ttl(msg: &[u8]) -> Option<u32> {
    let mut minimum = None;
    walk_records(msg, |rr| {
        if rr.rtype != 41 {
            let ttl = effective_ttl(rr.ttl);
            minimum = Some(minimum.map_or(ttl, |current: u32| current.min(ttl)));
        }
        Some(())
    })?;
    minimum
}

/// RFC 2308 negative-cache lifetime from an SOA in the AUTHORITY section:
/// `min(SOA RR TTL, SOA.MINIMUM)`. A negative answer without SOA is not reusable.
fn negative_cache_ttl(msg: &[u8]) -> Option<u32> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?
            .checked_add(4)
            .filter(|end| *end <= msg.len())?;
    }
    for _ in 0..ancount {
        let after_name = skip_name(msg, pos)?;
        let header_end = after_name.checked_add(10).filter(|end| *end <= msg.len())?;
        let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        pos = header_end
            .checked_add(rdlen)
            .filter(|end| *end <= msg.len())?;
    }

    let mut minimum_ttl = None;
    for _ in 0..nscount {
        let after_name = skip_name(msg, pos)?;
        let header_end = after_name.checked_add(10).filter(|end| *end <= msg.len())?;
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        let rr_ttl = u32::from_be_bytes([
            msg[after_name + 4],
            msg[after_name + 5],
            msg[after_name + 6],
            msg[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let record_end = header_end
            .checked_add(rdlen)
            .filter(|end| *end <= msg.len())?;
        if rtype == 6 {
            // SOA RDATA = MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM.
            let after_mname = skip_name(msg, header_end).filter(|p| *p <= record_end)?;
            let numeric = skip_name(msg, after_mname).filter(|p| *p <= record_end)?;
            if numeric.checked_add(20)? != record_end {
                return None;
            }
            let minimum = u32::from_be_bytes([
                msg[numeric + 16],
                msg[numeric + 17],
                msg[numeric + 18],
                msg[numeric + 19],
            ]);
            let candidate = rr_ttl.min(minimum);
            minimum_ttl =
                Some(minimum_ttl.map_or(candidate, |current: u32| current.min(candidate)));
        }
        pos = record_end;
    }
    minimum_ttl
}

/// CNAME/DNAME chains may be present in a NOERROR NODATA response. ANCOUNT alone
/// does not establish that the requested RRset exists. With a whole-message cache,
/// an unresolved chain/referral needs a negative SOA lifetime or cannot be reused.
fn answer_contains_question_type(msg: &[u8]) -> Option<bool> {
    if u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]) != 1 {
        return None;
    }
    let question_end = question_section_end(msg)?;
    let qtype = u16::from_be_bytes([msg[question_end - 4], msg[question_end - 3]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = question_end;
    for _ in 0..ancount {
        let after_name = skip_name(msg, pos)?;
        let header_end = after_name.checked_add(10).filter(|end| *end <= msg.len())?;
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        if rtype == qtype || qtype == 255 {
            return Some(true);
        }
        let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]);
        pos = header_end
            .checked_add(usize::from(rdlen))
            .filter(|end| *end <= msg.len())?;
    }
    Some(false)
}

fn response_cache_ttl(msg: &[u8]) -> Option<Duration> {
    if !dns_message_is_complete(msg) || msg[2] & 0x02 != 0 {
        return None; // TC is a retry instruction, never a reusable answer.
    }
    if edns(msg)
        .ok()?
        .is_some_and(|opt| opt.has_options || opt.version != 0)
    {
        return None; // Per-exchange options and unsupported versions are not reusable.
    }
    if has_transaction_signature(msg)? {
        return None; // TSIG and SIG(0) authenticate an exchange, not a reusable RRset.
    }
    // Cache only successful and standard negative outcomes. SERVFAIL, REFUSED,
    // FORMERR and other transient/policy errors must be retried upstream on the next query,
    // not amplified to every client for `dns.timeout_secs`.
    let rcode = msg[3] & 0x0F;
    if (rcode != 0 && rcode != 3) || dns_extended_rcode(msg)? != 0 {
        return None;
    }
    let message_ttl = record_min_ttl(msg);
    let is_negative = rcode == 3 || !answer_contains_question_type(msg)?;
    let negative_ttl = if is_negative {
        Some(negative_cache_ttl(msg)?)
    } else {
        None
    };
    let seconds = match (message_ttl, negative_ttl) {
        // Both NXDOMAIN and NOERROR/NODATA may carry an alias chain in ANSWER.
        (Some(answer), Some(negative)) => answer.min(negative),
        (Some(answer), None) => answer,
        (None, Some(negative)) => negative,
        (None, None) => return None,
    };
    if seconds == 0 {
        return None;
    }
    Some(Duration::from_secs(seconds as u64).min(MAX_CACHE_TTL))
}

fn response_is_retryable_error(msg: &[u8]) -> bool {
    let base_retryable = msg
        .get(3)
        .is_some_and(|flags| matches!(flags & 0x0F, 1 | 2 | 4 | 5));
    base_retryable || dns_extended_rcode(msg).is_some_and(|extended| extended != 0)
}

/// One DNS query over TCP (RFC 1035 §4.2.2: each message is prefixed with its 2-byte
/// big-endian length). Used both when `dns.upstream_protocol = tcp` and as the retry
/// path when a UDP answer comes back truncated. Returns the raw response message, or
/// `None` on any timeout/IO/protocol error — the caller then falls back. (S-14)
///
/// The whole exchange shares one deadline, so a resolver that accepts the connection and
/// then stalls cannot hold the task (and its in-flight permit) open.
async fn query_tcp(addr: &str, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let deadline = tokio::time::Instant::now() + timeout;
    let remaining =
        |d: tokio::time::Instant| d.saturating_duration_since(tokio::time::Instant::now());

    let mut stream =
        match tokio::time::timeout(remaining(deadline), tokio::net::TcpStream::connect(addr)).await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        };

    // Length-prefixed request.
    let len = u16::try_from(query.len()).ok()?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    if tokio::time::timeout(remaining(deadline), stream.write_all(&framed))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }

    // Length-prefixed response. The 2-byte prefix is what makes the >512-byte answers
    // that triggered the TCP retry readable in the first place.
    let mut len_buf = [0u8; 2];
    if tokio::time::timeout(remaining(deadline), stream.read_exact(&mut len_buf))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 {
        return None; // shorter than a DNS header — not a usable message
    }
    let mut resp = vec![0u8; resp_len];
    if tokio::time::timeout(remaining(deadline), stream.read_exact(&mut resp))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }
    Some(resp)
}

/// Answer one query, from the blocklist, the cache or an upstream — transport-agnostic.
///
/// Split out of `handle_query` so the TCP listener can share every bit of policy (blocklist,
/// cache, upstream selection and failover, cache admission). The alternative — a second copy
/// for TCP — is how two paths end up disagreeing about which names are blocked.
pub(crate) async fn resolve(
    cache: DnsCache,
    cfg: Arc<DnsConfig>,
    pref: Arc<AtomicUsize>,
    blocklist: Arc<HashSet<String>>,
    query: &[u8],
) -> Option<Vec<u8>> {
    let upstreams: Vec<_> = cfg
        .upstream
        .iter()
        .take(crate::config::server::DNS_MAX_UPSTREAMS)
        .filter_map(|address| address.parse().ok().map(|ip| SocketAddr::new(ip, 53)))
        .collect();
    resolve_with_upstreams(cache, cfg, pref, blocklist, query, &upstreams).await
}

// The same engine is exercised against ephemeral loopback resolvers in tests. Production
// always supplies validated configuration addresses on port 53; no new config syntax.
async fn resolve_with_upstreams(
    cache: DnsCache,
    cfg: Arc<DnsConfig>,
    pref: Arc<AtomicUsize>,
    blocklist: DnsBlocklist,
    query: &[u8],
    upstreams: &[SocketAddr],
) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None; // Ignore responses sent to the recursive query listener.
    }
    if query[2] & 0x78 != 0 {
        return Some(query_error_response(query, 4)); // NOTIMP: QUERY only.
    }
    if u16::from_be_bytes([query[4], query[5]]) > 1 {
        return Some(query_error_response(query, 1)); // RFC 9619: FORMERR.
    }
    if !dns_message_is_complete(query) {
        return None;
    }
    let query_opt = match edns(query) {
        Ok(opt) => opt,
        Err(()) => return Some(query_error_response(query, 1)),
    };
    if query_opt.is_some_and(|opt| opt.version != 0) {
        return Some(query_error_response(query, 16)); // BADVERS, with EDNS(0) metadata.
    }
    let signed_query = has_transaction_signature(query)?;
    let query = query.to_vec();
    let query_txid = [query[0], query[1]];

    if is_blocked(&query, &blocklist) {
        return blocked_response(&query);
    }

    // Cache key ignores the per-query transaction ID (bytes 0..2) so the same
    // question shares one entry regardless of txid.
    let mut cache_key = query.clone();
    cache_key[0] = 0;
    cache_key[1] = 0;

    let upstream_timeout = Duration::from_secs(
        cfg.timeout_secs
            .clamp(1, crate::config::server::DNS_MAX_TIMEOUT_SECS),
    );
    let cache_enabled =
        !signed_query && cfg.cache_size != 0 && query_opt.is_none_or(|opt| !opt.has_options);
    let cached = if cache_enabled {
        let cache_read = cache.read().await;
        cache_read
            .entries
            .get(cache_key.as_slice())
            .and_then(|(resp, time, entry_ttl)| {
                // Per-entry lifetime from the record, not the global network timeout. (S-14)
                let age = time.elapsed();
                if age < *entry_ttl {
                    Some((resp.to_vec(), age.as_secs()))
                } else {
                    None
                }
            })
    } else {
        None
    };
    if let Some((mut response, age_secs)) = cached {
        if response.len() >= 2 {
            response[0] = query_txid[0];
            response[1] = query_txid[1];
        }
        // Age the record TTLs by how long the answer has sat here.
        //
        // Only the transaction ID used to be rewritten, so a reply served one second before its
        // cache entry expired still claimed the FULL original TTL. Downstream resolvers and
        // stub clients cache on that number, which turns a 60-second record into up to 120
        // seconds of staleness — and the error compounds through every layer that caches. RFC
        // 2181 §5.2: a cached record is served with the remaining lifetime, not the original.
        // (Audit 2026-08-01, §10.)
        decrement_ttls(&mut response, age_secs.min(u32::MAX as u64) as u32);
        if let Some(opt) = query_opt {
            append_edns(&mut response, opt.payload, 0, 0, opt.flags & 0x8000);
        }
        return Some(response);
    }

    if upstreams.is_empty() {
        return None;
    }

    // (The in-flight permit is already held — acquired by the accept loop before spawn.)
    // A fresh ephemeral socket per query: no cross-query demux, so one slow
    // resolver only delays its own task.
    // `dns.upstream_protocol` was parsed, serialized back out and shown in the panel, but
    // NOTHING read it — every query went out over UDP regardless. An operator who set
    // `tcp` (e.g. because the network mangles UDP/53) got silent UDP anyway. (S-14)
    let force_tcp = cfg.upstream_protocol.eq_ignore_ascii_case("tcp");

    // Re-randomise the transaction ID for the UPSTREAM query.
    //
    // The client's txid used to travel upstream verbatim, and the only anti-spoof checks
    // were that same txid plus the upstream socket address. Against an off-path attacker
    // that is 32 bits (txid + ephemeral port). Against a VPN CLIENT it is ~15: the client
    // chooses the txid, knows the exact instant the query goes out, and — because the cache
    // is shared per profile and keyed on the question with the txid zeroed — a single
    // successful spoof poisons the answer for every other user of that profile. Only the
    // ephemeral source port remains unknown, and Linux's default range is ~28k.
    //
    // A fresh random txid restores the full 32 bits, and matching the QUESTION section
    // (below) closes the birthday variant where an attacker sprays answers for a name it
    // did not ask about. The client's txid is put back before the answer is cached or
    // returned. (Audit 2026-08-04, M-10.)
    // Transaction signatures cover message bytes. A transparent forwarder leaves
    // signed exchanges unchanged and never shares them through the ordinary cache.
    let upstream_txid: [u8; 2] = if signed_query {
        query_txid
    } else {
        let mut t = [0u8; 2];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut t);
        t
    };
    let mut query = query;
    query[0] = upstream_txid[0];
    query[1] = upstream_txid[1];
    let query = query;

    let start = pref.load(Ordering::Relaxed) % upstreams.len();
    let mut response = None;
    let mut last_upstream_error = None;
    let mut truncated_fallback = None;
    let query_deadline = tokio::time::Instant::now() + upstream_timeout;
    for attempt in 0..upstreams.len() {
        let now = tokio::time::Instant::now();
        let remaining = query_deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        // One configured timeout bounds the complete query, not each upstream in turn. Split
        // the remaining time so a dead preferred resolver cannot consume the whole budget
        // without giving the fallback resolver a chance.
        let attempts_left = u32::try_from(upstreams.len() - attempt)
            .unwrap_or(u32::MAX)
            .max(1);
        let attempt_timeout = remaining / attempts_left;
        if attempt_timeout.is_zero() {
            break;
        }
        let attempt_deadline = now + attempt_timeout;
        let idx = (start + attempt) % upstreams.len();
        let upstream_sa = upstreams[idx];
        let upstream_ip = upstream_sa.ip();
        let upstream_addr = upstream_sa.to_string();
        if force_tcp {
            if let Some(full) = query_tcp(&upstream_addr, &query, attempt_timeout).await {
                // Same anti-spoof check as the UDP path (TCP is connection-bound, so
                // the source is implicitly the resolver we dialled).
                if response_is_forwardable(&full, upstream_txid, &query) {
                    if response_is_retryable_error(&full) {
                        last_upstream_error = Some(full);
                        continue;
                    }
                    if full[2] & 0x02 != 0 {
                        truncated_fallback = Some(full);
                        continue; // TCP framing does not imply an untruncated DNS answer.
                    }
                    response = Some(full);
                    pref.store(idx, Ordering::Relaxed);
                    break;
                }
            }
            continue;
        }
        let bind_addr = if upstream_ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let upstream_sock = match UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(error) => {
                log::debug!("DNS: cannot open {bind_addr} upstream socket: {error}");
                continue;
            }
        };
        if upstream_sock.send_to(&query, upstream_sa).await.is_err() {
            continue;
        }
        // Accept only a reply that (a) came from the resolver we queried and (b)
        // carries the matching transaction ID — otherwise an off-/on-path spoof
        // could poison the cache. Bound the total wait by the configured timeout.
        // Sized from what the CLIENT advertised, with a 4 KiB floor.
        //
        // `recv_from` DISCARDS whatever does not fit, silently and with no short-read signal,
        // so the buffer has to be at least as large as the answer the upstream is entitled to
        // send — and that entitlement comes from the OPT record in the query, which is the
        // client's, forwarded verbatim. A fixed 4096 was right for the common advertisements
        // (1232/4096) and wrong for a client that asked for more: its answer came back chopped
        // mid-record and was forwarded as a malformed message. (S-14, extended 2026-08-01 §10.)
        let want = upstream_buf_size(&query);
        let mut resp_buf = vec![0u8; want];
        loop {
            let remaining = attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, upstream_sock.recv_from(&mut resp_buf)).await {
                Ok(Ok((m, from))) => {
                    // Compare the FULL socket address, not just the IP. A reply is only ours
                    // if it came back from the port we sent to; accepting any port on the
                    // right host lets anything else on that machine — or anything that can
                    // spoof its address — answer for the resolver, and the txid below is only
                    // 16 bits of defence.
                    if from != upstream_sa {
                        continue; // not from the queried resolver — ignore
                    }
                    if !response_matches(&resp_buf[..m], upstream_txid, &query) {
                        continue; // wrong txid/question — spoof or stale, ignore
                    }
                    // TC is an explicit retry instruction. An exact buffer fill is the one
                    // case where `recv_from` cannot distinguish a complete datagram from one
                    // it cut off. Either condition needs one (not two) TCP retry.
                    let truncated = resp_buf[2] & 0x02 != 0;
                    let possibly_cut_off = m == resp_buf.len();
                    if truncated || possibly_cut_off {
                        if truncated {
                            log::debug!(
                                "DNS: truncated reply from {} — retrying over TCP",
                                upstream_sa
                            );
                        } else {
                            log::debug!(
                                "DNS: reply from {} exactly filled the {}-byte buffer — may \
                                 have been cut off, retrying over TCP",
                                upstream_sa,
                                resp_buf.len()
                            );
                        }
                        let tcp_budget =
                            attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
                        if let Some(full) = query_tcp(&upstream_addr, &query, tcp_budget).await {
                            if response_is_forwardable(&full, upstream_txid, &query) {
                                if response_is_retryable_error(&full) {
                                    last_upstream_error = Some(full);
                                    break;
                                }
                                if full[2] & 0x02 != 0 {
                                    truncated_fallback = Some(full);
                                    break; // Give other upstreams the remaining query budget.
                                }
                                response = Some(full);
                                pref.store(idx, Ordering::Relaxed);
                                break;
                            }
                        }
                        // Give the remaining resolvers a chance before falling back to TC.
                        // An exact buffer fill without TC may have been cut mid-record and is
                        // never safe to forward. An explicit TC response is structurally useful:
                        // keep it only as a last resort so the downstream client can retry TCP.
                        if truncated
                            && response_is_forwardable(&resp_buf[..m], upstream_txid, &query)
                        {
                            truncated_fallback = Some(resp_buf[..m].to_vec());
                        }
                        break;
                    }
                    if !response_is_forwardable(&resp_buf[..m], upstream_txid, &query) {
                        break; // corrupt framing or unsolicited signature: try another resolver
                    }
                    if response_is_retryable_error(&resp_buf[..m]) {
                        // Return the last real DNS error if every resolver fails, but first
                        // try the next upstream instead of making this one the preferred
                        // source of SERVFAIL/REFUSED for every subsequent client.
                        last_upstream_error = Some(resp_buf[..m].to_vec());
                        break;
                    }
                    response = Some(resp_buf[..m].to_vec());
                    pref.store(idx, Ordering::Relaxed);
                    break;
                }
                _ => break, // timeout or socket error → try next upstream
            }
        }
        if response.is_some() {
            break;
        }
    }

    if response.is_none() {
        response = last_upstream_error;
    }
    if response.is_none() {
        if let Some(fallback) = truncated_fallback {
            response = Some(fallback);
        }
    }
    if let Some(mut resp) = response {
        // Restore the ordinary query's client ID. Signed exchanges already use
        // that same ID throughout, so these assignments preserve their bytes.
        resp[0] = query_txid[0];
        resp[1] = query_txid[1];

        // Cache lifetime from the record itself, clamped. A TTL of 0 means "do not cache"
        // (RFC 2181 §8) and is honoured by skipping the insert entirely — it is used for
        // things like round-robin load balancing, where caching defeats the point. Negative
        // NXDOMAIN/NODATA responses use RFC 2308's min(SOA TTL, SOA.MINIMUM); without a valid
        // authority SOA they are not reusable. (S-14)
        if !cache_enabled {
            return Some(resp);
        }
        let Some(entry_ttl) = response_cache_ttl(&resp) else {
            return Some(resp);
        };

        let Some(stored_response) = cache_response_bytes(&resp, query_opt) else {
            return Some(resp);
        };
        let cache_limit = cfg
            .cache_size
            .min(crate::config::server::DNS_MAX_CACHE_ENTRIES);
        let mut cache_write = cache.write().await;
        insert_cache_entry(
            &mut cache_write,
            cache_key,
            stored_response,
            entry_ttl,
            cache_limit,
        );
        return Some(resp);
    }
    None
}

// Account for retained queries as well as answers. Evict in batches under pressure
// to amortise full-map scans, without cloning potentially large victim keys.
fn insert_cache_entry(
    cache: &mut DnsCacheStore,
    cache_key: Vec<u8>,
    resp: Vec<u8>,
    entry_ttl: Duration,
    cache_limit: usize,
) {
    let cache_limit = cache_limit.min(crate::config::server::DNS_MAX_CACHE_ENTRIES);
    let incoming = cache_key.len().saturating_add(resp.len());
    if cache_limit == 0 || incoming > MAX_CACHE_PAYLOAD_BYTES || entry_ttl.is_zero() {
        return;
    }
    if let Some((key, (value, _, _))) = cache.entries.remove_entry(cache_key.as_slice()) {
        cache.payload_bytes -= key.len() + value.len();
    }
    if cache.entries.len() >= cache_limit
        || cache.payload_bytes + incoming > MAX_CACHE_PAYLOAD_BYTES
    {
        let now = Instant::now();
        cache.entries.retain(|key, (value, inserted, ttl)| {
            if now.duration_since(*inserted) < *ttl {
                true
            } else {
                cache.payload_bytes -= key.len() + value.len();
                false
            }
        });
        let count_pressure = cache.entries.len() >= cache_limit;
        let byte_pressure = cache.payload_bytes + incoming > MAX_CACHE_PAYLOAD_BYTES;
        let target_count = if count_pressure {
            cache_limit.saturating_sub((cache_limit / 10).max(1))
        } else {
            cache.entries.len()
        };
        let target_bytes = if byte_pressure {
            (MAX_CACHE_PAYLOAD_BYTES - incoming).min(MAX_CACHE_PAYLOAD_BYTES * 9 / 10)
        } else {
            cache.payload_bytes
        };
        let mut remaining_count = cache.entries.len();
        cache.entries.retain(|key, (value, _, _)| {
            if remaining_count > target_count || cache.payload_bytes > target_bytes {
                remaining_count -= 1;
                cache.payload_bytes -= key.len() + value.len();
                false
            } else {
                true
            }
        });
    }
    cache.payload_bytes += incoming;
    cache.entries.insert(
        cache_key.into_boxed_slice(),
        (resp.into_boxed_slice(), Instant::now(), entry_ttl),
    );
}

/// How large a reply the UPSTREAM may legitimately send us, which is what the client asked
/// for — its OPT record travels upstream verbatim — with a 4 KiB floor so the common case
/// keeps its old headroom, and the UDP maximum as the ceiling.
fn upstream_buf_size(query: &[u8]) -> usize {
    advertised_udp_size(query).clamp(4096, 65_535)
}

/// The EDNS advertisement belongs to the current exchange; malformed messages
/// never get to negotiate a larger receive buffer.
fn advertised_udp_size(query: &[u8]) -> usize {
    edns(query)
        .ok()
        .flatten()
        .map_or(512, |opt| usize::from(opt.payload).max(512))
}

/// Offset of the first ADDITIONAL record, stepping over the question, answer and authority
/// sections. `None` on anything malformed.
fn additional_section_start(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?
            .checked_add(4)
            .filter(|end| *end <= msg.len())?; // QTYPE + QCLASS
    }
    for _ in 0..(ancount + nscount) {
        pos = skip_name(msg, pos)?;
        if pos.checked_add(10)? > msg.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos = pos
            .checked_add(10)?
            .checked_add(rdlen)
            .filter(|end| *end <= msg.len())?;
    }
    Some(pos)
}

/// Detect transaction authentication without validating its keys or MAC. RRSIG
/// (46) and legacy SIG covering an RRset are distinct from SIG(0) (24, covered=0).
fn has_transaction_signature(msg: &[u8]) -> Option<bool> {
    let mut pos = additional_section_start(msg)?;
    let arcount = u16::from_be_bytes([msg[10], msg[11]]);
    for _ in 0..arcount {
        let after_name = skip_name(msg, pos)?;
        let header_end = after_name.checked_add(10).filter(|end| *end <= msg.len())?;
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([
            msg[after_name + 8],
            msg[after_name + 9],
        ]));
        pos = header_end
            .checked_add(rdlen)
            .filter(|end| *end <= msg.len())?;
        if rtype == 250 {
            return Some(true);
        }
        if rtype == 24 {
            if rdlen < 2 {
                return None;
            }
            if msg[header_end..header_end + 2] == [0, 0] {
                return Some(true);
            }
        }
    }
    Some(false)
}

/// Unsigned requests use a random upstream ID. An unsolicited signed response
/// cannot be relayed with the client's ID without changing authenticated bytes.
fn response_is_forwardable(resp: &[u8], txid: [u8; 2], query: &[u8]) -> bool {
    if !response_matches(resp, txid, query) || !dns_message_is_complete(resp) {
        return false;
    }
    let (Ok(query_opt), Ok(response_opt)) = (edns(query), edns(resp)) else {
        return false;
    };
    if response_opt.is_some_and(|opt| opt.version != 0 || query_opt.is_none()) {
        return false;
    }
    match has_transaction_signature(resp) {
        Some(false) => true,
        Some(true) => has_transaction_signature(query) == Some(true),
        None => false,
    }
}

/// Local errors contain a header plus supported EDNS metadata when the OPT is
/// valid. Unvalidated questions, request RRs and option payloads are not reflected.
fn query_error_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let mut response = vec![0; 12];
    response[..2].copy_from_slice(&query[..2]);
    response[2] = 0x80 | (query[2] & 0x79); // QR, opcode and RD
    response[3] = 0x80 | (query[3] & 0x10) | (rcode as u8 & 15); // RA and CD; never AD
    if let Ok(Some(opt)) = edns(query) {
        append_edns(
            &mut response,
            opt.payload,
            (rcode >> 4) as u8,
            0,
            opt.flags & 0x8000,
        );
    }
    response
}

#[derive(Clone, Copy)]
struct Edns {
    start: usize,
    end: usize,
    payload: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    has_options: bool,
}

/// Parse the single additional-section OPT and bound each option's TLV. Unknown
/// option codes are legal and relayed unchanged. Their semantics are not inferred.
fn edns(msg: &[u8]) -> Result<Option<Edns>, ()> {
    let mut opt = None;
    walk_records(msg, |rr| {
        if rr.rtype != 41 {
            return Some(());
        }
        if opt.is_some() || rr.section != 2 || msg[rr.start] != 0 || rr.data != rr.start + 11 {
            return None;
        }
        let version = ((rr.ttl >> 16) & 0xff) as u8;
        // Only EDNS(0)'s option format is known. Other versions get BADVERS.
        if version == 0 {
            let mut pos = rr.data;
            while pos < rr.end {
                let header_end = pos.checked_add(4).filter(|end| *end <= rr.end)?;
                let len = usize::from(u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]));
                pos = header_end.checked_add(len).filter(|end| *end <= rr.end)?;
            }
        }
        opt = Some(Edns {
            start: rr.start,
            end: rr.end,
            payload: rr.class,
            extended_rcode: (rr.ttl >> 24) as u8,
            version,
            flags: rr.ttl as u16,
            has_options: rr.data != rr.end,
        });
        Some(())
    })
    .ok_or(())?;
    Ok(opt)
}

fn dns_extended_rcode(msg: &[u8]) -> Option<u8> {
    Some(edns(msg).ok()?.map_or(0, |opt| opt.extended_rcode))
}

/// Construct only the supported EDNS metadata; never echo client options into a
/// synthetic reply. Local errors and cached answers negotiate EDNS afresh.
fn append_edns(msg: &mut Vec<u8>, payload: u16, rcode: u8, version: u8, flags: u16) {
    msg.extend_from_slice(&[0, 0, 41]);
    msg.extend_from_slice(&payload.max(512).to_be_bytes());
    msg.extend_from_slice(&[rcode, version]);
    msg.extend_from_slice(&flags.to_be_bytes());
    msg.extend_from_slice(&[0, 0]);
    let count = u16::from_be_bytes([msg[10], msg[11]]) + 1;
    msg[10..12].copy_from_slice(&count.to_be_bytes());
}

/// Strip a terminal empty OPT before storage. Removing an OPT in the middle
/// would invalidate later compression offsets, so those responses bypass cache.
fn cache_response_bytes(msg: &[u8], query_opt: Option<Edns>) -> Option<Vec<u8>> {
    let response_opt = edns(msg).ok()?;
    match (query_opt, response_opt) {
        (None, None) => Some(msg.to_vec()),
        (Some(query), Some(reply))
            if !query.has_options
                && !reply.has_options
                && reply.end == msg.len()
                && reply.version == 0
                && reply.extended_rcode == 0
                && reply.flags == query.flags & 0x8000 =>
        {
            let mut stored = msg[..reply.start].to_vec();
            let count = u16::from_be_bytes([stored[10], stored[11]]) - 1;
            stored[10..12].copy_from_slice(&count.to_be_bytes());
            Some(stored)
        }
        _ => None,
    }
}

/// Fit an unsigned UDP reply to the advertised size, setting TC for TCP retry.
/// A signed reply that does not fit is dropped: without its key we cannot create
/// an authenticated replacement. Signed clients need TCP or sufficient EDNS space.
///
/// This proxy used to forward the answer WHOLE however large it was, because setting TC without
/// a TCP listener would have sent the client to a port where nothing answers — a working lookup
/// turned into a failing one. Now that the listener exists, TC means what it says.
///
/// The replacement contains the header, question and, for EDNS peers, a fresh
/// OPT carrying the extended RCODE/version/flags. Answer and authority counts
/// become zero; optional TLVs are omitted. No RR is chopped mid-record.
pub(crate) fn apply_udp_size_limit(query: &[u8], resp: Vec<u8>) -> Option<Vec<u8>> {
    // resolve can intentionally return a header-only FORMERR for an invalid OPT.
    // Use the legacy size floor in that case so the UDP listener can deliver it.
    let query_opt = edns(query).ok().flatten();
    let response_opt = edns(&resp).ok()?;
    if query_opt.is_none() && response_opt.is_some() {
        return None; // A non-EDNS peer cannot interpret an unsolicited extended RCODE.
    }
    let limit = advertised_udp_size(query);
    if resp.len() <= limit {
        return Some(resp);
    }
    if has_transaction_signature(&resp)? {
        // We have no key to sign a shorter replacement. Require TCP or a large
        // enough EDNS advertisement rather than stripping authentication.
        return None;
    }
    // Keep the validated question so the downstream client can match its retry.
    let q_end = question_section_end(query)?;
    let mut out = Vec::with_capacity(q_end);
    out.extend_from_slice(&query[..q_end]);
    // The FLAGS come from the real answer, not from the query.
    //
    // Building them from the query and forcing NOERROR discarded what the resolver actually
    // said: an oversized NXDOMAIN went out as NOERROR+TC, and RA (recursion available), AA and
    // AD were lost with it. A stub that trusts the truncated header — many do, before deciding
    // whether the TCP retry is even worth it — was told the wrong thing about the answer it
    // was about to fetch. Copy bytes 2..4 from the response and set TC on top; only QR is
    // forced, because a response is what this is. (Audit 2026-08-01, §10.)
    if resp.len() >= 4 {
        out[2] = resp[2];
        out[3] = resp[3];
    }
    out[2] |= 0x80; // QR: this is a response
    out[2] |= 0x02; // TC: truncated — ask again over TCP
                    // QDCOUNT is left alone on purpose — the question IS carried, and a resolver matches the
                    // truncated reply to its outstanding query by it.
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if let Some(query_opt) = query_opt {
        let extended = response_opt.map_or(0, |opt| opt.extended_rcode);
        let version = response_opt.map_or(0, |opt| opt.version);
        let flags = response_opt.map_or(query_opt.flags & 0x8000, |opt| opt.flags);
        append_edns(&mut out, query_opt.payload, extended, version, flags);
    }
    Some(out)
}

/// Offset just past the question section.
/// Is this upstream reply actually the answer to the query we sent?
///
/// Checks the transaction ID AND that the QUESTION section comes back byte-identical.
/// The txid alone is 16 bits; without the question match an attacker spraying answers can
/// win the birthday race with a reply about a name we never asked for and still have it
/// cached under our key. Both are cheap and neither is optional. (Audit 2026-08-04, M-10.)
fn response_matches(resp: &[u8], txid: [u8; 2], query: &[u8]) -> bool {
    if resp.len() < 12 || resp[0] != txid[0] || resp[1] != txid[1] {
        return false;
    }
    // QR bit must be set — a reply, not a reflected query.
    if resp[2] & 0x80 == 0 || query.len() < 12 || resp[2] & 0x78 != query[2] & 0x78 {
        return false;
    }
    match (question_section_end(query), question_section_end(resp)) {
        (Some(qe), Some(re)) => {
            // QDCOUNT must agree too, else "no question" trivially matches "no question".
            query[4..6] == resp[4..6] && qe == re && query[12..qe] == resp[12..re]
        }
        _ => false,
    }
}

fn question_section_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?
            .checked_add(4)
            .filter(|end| *end <= msg.len())?;
    }
    Some(pos)
}

/// Construct a self-contained NXDOMAIN response for a blocked name.
///
/// Copying the whole request and only changing FLAGS also copied any client-supplied
/// ANSWER/AUTHORITY/ADDITIONAL records while their counts still claimed they were part of
/// our response. Besides reflecting arbitrary payload, that produced contradictory NXDOMAIN
/// packets. Keep only the validated question and explicitly clear every resource-record count.
fn blocked_response(query: &[u8]) -> Option<Vec<u8>> {
    let q_end = question_section_end(query)?;
    let mut response = query[..q_end].to_vec();
    // Preserve OPCODE and RD from the request. This proxy provides recursion (RA), does not
    // authenticate the synthetic answer (AD=0), and returns NXDOMAIN.
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80 | (query[3] & 0x10) | 0x03;
    response[6..8].copy_from_slice(&0u16.to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    response[10..12].copy_from_slice(&0u16.to_be_bytes());
    if let Some(opt) = edns(query).ok()? {
        append_edns(&mut response, opt.payload, 0, 0, opt.flags & 0x8000);
    }
    Some(response)
}

pub(crate) fn compile_blocklist(raw: &[String]) -> DnsBlocklist {
    Arc::new(
        raw.iter()
            .filter_map(|domain| crate::config::server::normalize_blocklist_domain(domain))
            .collect(),
    )
}

fn is_blocked(query: &[u8], blocklist: &HashSet<String>) -> bool {
    if blocklist.is_empty() {
        return false;
    }

    let Some(domain) = first_question_name(query) else {
        return false;
    };
    let mut candidate = domain.as_str();
    loop {
        if blocklist.contains(candidate) {
            return true;
        }
        let Some(dot) = candidate.find('.') else {
            return false;
        };
        candidate = &candidate[dot + 1..];
    }
}

/// Decode the first question name, including legal compression pointers, with strict loop and
/// length bounds. Blocklist matching must not interpret bytes from QTYPE, EDNS or another
/// section as labels when a client sends malformed framing.
fn first_question_name(query: &[u8]) -> Option<String> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) == 0 {
        return None;
    }
    let mut labels = Vec::new();
    walk_name(query, 12, |label| labels.push(label))?;
    let mut domain = String::from_utf8(labels.join(&b"."[..])).ok()?;
    domain.make_ascii_lowercase();
    Some(domain)
}

#[cfg(test)]
mod tests {
    //! Coverage for the answer-TTL parser (S-14). It walks attacker-influenced bytes —
    //! an upstream reply is untrusted input — so the cases that matter are the malformed
    //! ones: it must return None, never panic or loop.
    use super::*;

    fn typed_response(rtype: u16, class: u16, data: &[u8]) -> Vec<u8> {
        let mut msg = response(&[], true);
        let question_end = question_section_end(&msg).unwrap();
        msg[question_end - 4..question_end - 2].copy_from_slice(&rtype.to_be_bytes());
        msg[question_end - 2..question_end].copy_from_slice(&class.to_be_bytes());
        msg[7] = 1;
        msg.extend_from_slice(&[0xc0, 12]);
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&class.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(data);
        msg
    }

    #[test]
    fn rdata_validation_accepts_known_records_and_preserves_unknown_types() {
        for (rtype, data) in [
            (1, vec![192, 0, 2, 1]),
            (28, vec![0; 16]),
            (2, vec![0xc0, 12]),
            (5, vec![0xc0, 12]),
            (12, vec![0]),
            (39, vec![0]),
            (15, vec![0, 10, 0xc0, 12]),
            (33, vec![0, 1, 0, 2, 0, 53, 0]),
            (16, vec![0, 3, b'a', b'b', b'c']),
            (65000, vec![0xff, 0xc0, 0x0c]),
            (65001, vec![]),
        ] {
            let msg = typed_response(rtype, 1, &data);
            assert!(dns_message_is_complete(&msg), "type {rtype}");
            assert_eq!(response_cache_ttl(&msg), Some(Duration::from_secs(60)));
        }
        // An A RR in an unknown class need not have the IN class's four-byte format.
        assert!(dns_message_is_complete(&typed_response(1, 65000, &[0xff])));
        assert!(dns_message_is_complete(&with_soa(
            response(&[60], true),
            60,
            30
        )));
        for (rtype, data) in [
            (1, vec![0; 3]),
            (28, vec![0; 15]),
            (2, vec![]),
            (5, vec![0xc0, 0]),
            (12, vec![0, 0]),
            (39, vec![3, b'a']),
            (15, vec![0, 10]),
            (33, vec![0; 6]),
            (16, vec![]),
            (16, vec![4, b'a']),
            (6, vec![0; 21]),
        ] {
            let msg = typed_response(rtype, 1, &data);
            assert!(!dns_message_is_complete(&msg), "type {rtype}");
            assert_eq!(response_cache_ttl(&msg), None);
        }
        let mut cycle = typed_response(5, 1, &[0xc0, 12]);
        let data_at = cycle.len() - 2;
        cycle[data_at + 1] = u8::try_from(data_at).unwrap();
        assert!(!dns_message_is_complete(&cycle));
    }

    #[tokio::test]
    async fn local_edns_errors_and_blocklist_replies_negotiate_without_echoing_options() {
        let cfg = Arc::new(DnsConfig {
            upstream: Vec::new(),
            ..serde_json::from_str("{}").unwrap()
        });
        for version in [0, 1] {
            let request = with_opt(query(None), 0, version, 0x8000, &[0xfd, 0xe8, 0, 1, 42]);
            let answer = resolve(
                new_cache(),
                cfg.clone(),
                Arc::new(AtomicUsize::new(0)),
                compile_blocklist(&["example.com".into()]),
                &request,
            )
            .await
            .unwrap();
            let opt = edns(&answer).unwrap().unwrap();
            assert_eq!(opt.version, 0);
            assert_eq!(opt.flags, 0x8000);
            assert!(!opt.has_options);
            assert_eq!(
                u16::from(opt.extended_rcode) * 16 + u16::from(answer[3] & 15),
                if version == 0 { 3 } else { 16 }
            );
            assert!(dns_message_is_complete(&answer));
        }
    }

    #[tokio::test]
    async fn cached_edns_answers_store_no_opt_and_rebuild_metadata_per_exchange() {
        let mut request = query(Some(1232));
        let opt_at = additional_section_start(&request).unwrap();
        request[opt_at + 7] = 0x80; // DO
        let reply = with_opt(response(&[60], true), 0, 0, 0x8000, &[]);
        let upstream = test_upstream(Some(reply), None).await;
        let cfg = Arc::new(DnsConfig {
            upstream_protocol: "udp".into(),
            timeout_secs: 1,
            ..serde_json::from_str("{}").unwrap()
        });
        let cache = new_cache();
        let first = resolve_with_upstreams(
            cache.clone(),
            cfg.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request,
            &[upstream.address],
        )
        .await
        .unwrap();
        assert!(edns(&first).unwrap().is_some());
        let mut key = request.clone();
        key[..2].fill(0);
        {
            let mut store = cache.write().await;
            let entry = store.entries.get_mut(key.as_slice()).unwrap();
            assert!(edns(&entry.0).unwrap().is_none(), "OPT must not be stored");
            entry.1 = Instant::now() - Duration::from_secs(10);
        }
        request[..2].copy_from_slice(&[0x12, 0x34]);
        let second = resolve_with_upstreams(
            cache.clone(),
            cfg,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(&second[..2], &[0x12, 0x34]);
        assert!(record_min_ttl(&second).unwrap() <= 50);
        let opt = edns(&second).unwrap().unwrap();
        assert_eq!(
            (opt.payload, opt.version, opt.flags, opt.has_options),
            (1232, 0, 0x8000, false)
        );
        assert!(dns_message_is_complete(&second));
        assert_cache_budget(&*cache.read().await, 1000);
    }

    #[tokio::test]
    async fn unknown_edns_options_are_forwarded_without_cache_reuse() {
        // Unknown options are opaque; only their outer TLV length is interpreted.
        let options = [0xfd, 0xe8, 0, 3, 0xff, 0xc0, 12];
        let request = with_opt(query(None), 0, 0, 0, &options);
        let cfg = Arc::new(DnsConfig {
            upstream_protocol: "tcp".into(),
            timeout_secs: 1,
            ..serde_json::from_str("{}").unwrap()
        });
        let cache = new_cache();
        for ttl in [60, 30] {
            let reply = with_opt(response(&[ttl], true), 0, 0, 0, &options);
            let upstream = test_upstream(None, Some(reply.clone())).await;
            let answer = resolve_with_upstreams(
                cache.clone(),
                cfg.clone(),
                Arc::new(AtomicUsize::new(0)),
                Arc::new(HashSet::new()),
                &request,
                &[upstream.address],
            )
            .await
            .unwrap();
            assert_eq!(&answer[2..], &reply[2..]);
            assert!(cache.read().await.entries.is_empty());
        }
    }

    #[test]
    fn edns_cache_exclusions_preserve_offsets_and_negotiation() {
        let request = query(Some(1232));
        let query_opt = edns(&request).unwrap();
        let ordinary = with_opt(response(&[60], true), 0, 0, 0, &[]);
        let nonterminal = with_extra_a(ordinary.clone(), 10, 30);
        assert!(dns_message_is_complete(&nonterminal));
        assert!(response_is_forwardable(
            &nonterminal,
            [nonterminal[0], nonterminal[1]],
            &request
        ));
        assert!(cache_response_bytes(&nonterminal, query_opt).is_none());
        assert!(cache_response_bytes(&response(&[60], true), query_opt).is_none()); // legacy upstream
        assert!(cache_response_bytes(&ordinary, None).is_none()); // unsolicited OPT
        let opt = with_opt(response(&[60], true), 0, 0, 0x8000, &[]);
        assert_eq!(record_min_ttl(&opt), Some(60), "OPT flags are not a TTL");
        for offset in [8, 10] {
            assert_eq!(
                response_cache_ttl(&with_extra_a(response(&[60], true), offset, 0x8000_0001)),
                None
            );
        }
    }

    #[tokio::test]
    async fn malformed_edns_or_rdata_upstream_replies_fail_over_on_udp_and_tcp() {
        let duplicate = with_opt(with_opt(response(&[60], true), 0, 0, 0, &[]), 0, 0, 0, &[]);
        let short_option = with_opt(response(&[60], true), 0, 0, 0, &[0, 10, 0, 8, 1]);
        let mut misplaced = with_opt(response(&[60], true), 0, 0, 0, &[]);
        misplaced[7] = 2;
        misplaced[11] = 0;
        let version = with_opt(response(&[60], true), 0, 1, 0, &[]);
        let invalid_a = typed_response(1, 1, &[192, 0, 2]);
        for force_tcp in [false, true] {
            for bad in [&duplicate, &short_option, &misplaced, &version, &invalid_a] {
                let first = test_upstream(
                    (!force_tcp).then(|| bad.clone()),
                    force_tcp.then(|| bad.clone()),
                )
                .await;
                let good = with_opt(response(&[30], true), 0, 0, 0, &[]);
                let second = test_upstream(
                    (!force_tcp).then(|| good.clone()),
                    force_tcp.then_some(good),
                )
                .await;
                let cfg = Arc::new(DnsConfig {
                    upstream_protocol: if force_tcp { "tcp" } else { "udp" }.into(),
                    timeout_secs: 2,
                    ..serde_json::from_str("{}").unwrap()
                });
                let pref = Arc::new(AtomicUsize::new(0));
                let answer = resolve_with_upstreams(
                    new_cache(),
                    cfg,
                    pref.clone(),
                    Arc::new(HashSet::new()),
                    &query(Some(1232)),
                    &[first.address, second.address],
                )
                .await
                .unwrap();
                assert_eq!(record_min_ttl(&answer), Some(30));
                assert_eq!(pref.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[tokio::test]
    async fn ipv6_upstreams_support_udp_and_tcp_with_edns() {
        for force_tcp in [false, true] {
            let reply = with_opt(response(&[60], true), 0, 0, 0, &[]);
            let upstream = test_upstream_at(
                "[::1]:0",
                (!force_tcp).then(|| reply.clone()),
                force_tcp.then_some(reply),
            )
            .await;
            let cfg = Arc::new(DnsConfig {
                upstream_protocol: if force_tcp { "tcp" } else { "udp" }.into(),
                timeout_secs: 1,
                ..serde_json::from_str("{}").unwrap()
            });
            let answer = resolve_with_upstreams(
                new_cache(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(HashSet::new()),
                &query(Some(1232)),
                &[upstream.address],
            )
            .await
            .unwrap();
            assert_eq!(record_min_ttl(&answer), Some(60));
            assert!(edns(&answer).unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn edns_options_bypass_existing_cache_even_when_upstream_omits_options() {
        let request = with_opt(query(None), 0, 0, 0, &[0xfd, 0xe8, 0, 0]);
        let cache = new_cache();
        let mut key = request.clone();
        key[..2].fill(0);
        insert_cache_entry(
            &mut *cache.write().await,
            key.clone(),
            response(&[300], true),
            Duration::from_secs(300),
            8,
        );
        let upstream =
            test_upstream(Some(with_opt(response(&[30], true), 0, 0, 0, &[])), None).await;
        let cfg = Arc::new(DnsConfig {
            upstream_protocol: "udp".into(),
            // This checks response/cache contents, not timing; allow headroom for parallel tests.
            timeout_secs: 5,
            ..serde_json::from_str("{}").unwrap()
        });
        let answer = resolve_with_upstreams(
            cache.clone(),
            cfg,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request,
            &[upstream.address],
        )
        .await
        .unwrap();
        assert_eq!(record_min_ttl(&answer), Some(30));
        assert_eq!(
            record_min_ttl(&cache.read().await.entries.get(key.as_slice()).unwrap().0),
            Some(300)
        );
    }

    #[test]
    fn dns_record_and_edns_parsers_handle_truncations_and_byte_mutations() {
        let corpus = [
            response(&[60], true),
            cname_response(60),
            with_soa(response(&[60], true), 30, 5),
            with_opt(
                response(&[60], true),
                1,
                0,
                0x8000,
                &[0xfd, 0xe8, 0, 3, 1, 2, 3],
            ),
        ];
        let request = query(Some(512));
        let check = |msg: &[u8]| {
            let _ = dns_message_is_complete(msg);
            let _ = response_cache_ttl(msg);
            let _ = edns(msg);
            let _ = advertised_udp_size(msg);
            let _ = apply_udp_size_limit(&request, msg.to_vec());
        };
        for full in corpus {
            for cut in 0..=full.len() {
                check(&full[..cut]);
            }
            for pos in 0..full.len() {
                for value in [0, 1, 63, 192, 255] {
                    let mut mutated = full.clone();
                    mutated[pos] = value;
                    check(&mutated);
                }
            }
        }
    }

    fn with_opt(
        mut msg: Vec<u8>,
        extended: u8,
        version: u8,
        flags: u16,
        options: &[u8],
    ) -> Vec<u8> {
        let count = u16::from_be_bytes([msg[10], msg[11]]) + 1;
        msg[10..12].copy_from_slice(&count.to_be_bytes());
        msg.extend_from_slice(&[0, 0, 41, 4, 208, extended, version]); // root, OPT, 1232 bytes
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(options);
        msg
    }

    fn with_extra_a(mut msg: Vec<u8>, count_offset: usize, ttl: u32) -> Vec<u8> {
        let count = u16::from_be_bytes([msg[count_offset], msg[count_offset + 1]]) + 1;
        msg[count_offset..count_offset + 2].copy_from_slice(&count.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        msg
    }

    #[test]
    fn audit_whole_message_cache_obeys_authority_and_additional_ttls() {
        for section in [8, 10] {
            for ttl in [0, 1, 5] {
                let answer = with_extra_a(response(&[300], true), section, ttl);
                assert_eq!(
                    response_cache_ttl(&answer),
                    (ttl > 0).then(|| Duration::from_secs(u64::from(ttl)))
                );
            }
        }
    }

    #[test]
    fn audit_high_bit_ttl_is_not_cacheable() {
        for ttl in [0x8000_0000, 0xffff_ffff] {
            assert_eq!(response_cache_ttl(&response(&[ttl], true)), None);
        }
    }

    #[tokio::test]
    async fn audit_malformed_edns_requests_get_formerr() {
        let duplicate = with_opt(query(Some(1232)), 0, 0, 0, &[]);
        let short_option = with_opt(query(None), 0, 0, 0, &[0, 10, 0, 8, 1]);
        let mut non_root = query(Some(1232));
        let start = additional_section_start(&non_root).unwrap();
        non_root.splice(start..start + 1, [0xc0, 12]);
        for request in [duplicate, short_option, non_root] {
            let cfg = Arc::new(DnsConfig {
                upstream: Vec::new(),
                ..serde_json::from_str("{}").unwrap()
            });
            let answer = resolve(
                new_cache(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(HashSet::new()),
                &request,
            )
            .await
            .expect("invalid OPT must get FORMERR before upstream");
            assert_eq!(answer[3] & 15, 1);
            assert!(
                apply_udp_size_limit(&request, answer).is_some(),
                "UDP must deliver local FORMERR even when the request OPT is invalid"
            );
        }
    }

    #[test]
    fn audit_truncation_keeps_extended_error_code() {
        let request = query(Some(512));
        let reply = with_opt(response(&[60; 40], true), 1, 0, 0x8000, &[]);
        let truncated = apply_udp_size_limit(&request, reply).unwrap();
        assert_eq!(
            dns_extended_rcode(&truncated),
            Some(1),
            "BADVERS must not turn into NOERROR"
        );
        assert!(truncated.len() <= 512);
    }

    #[test]
    fn audit_structurally_framed_bad_rdata_is_not_forwardable() {
        for rtype in [1u16, 28, 5, 16] {
            let mut answer = response(&[], true);
            answer[7] = 1;
            answer.extend_from_slice(&[0xc0, 12]);
            answer.extend_from_slice(&rtype.to_be_bytes());
            answer.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, 1, 0xff]);
            assert!(
                !dns_message_is_complete(&answer),
                "bad RDATA for type {rtype} accepted"
            );
        }
    }

    #[test]
    fn audit_edns_exchange_options_are_not_cached() {
        let cookie = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let reply = with_opt(response(&[60], true), 0, 0, 0, &cookie);
        assert_eq!(response_cache_ttl(&reply), None);
    }

    fn with_transaction_signature(mut msg: Vec<u8>, rtype: u16) -> Vec<u8> {
        let mut data = Vec::new();
        if rtype == 250 {
            data.extend_from_slice(b"\x0bhmac-sha256\0");
            data.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 60, 0, 32]);
            data.extend_from_slice(&[0x5a; 32]); // opaque MAC: relay tests do not verify keys
            data.extend_from_slice(&msg[..2]); // Original ID
            data.extend_from_slice(&[0, 0, 0, 0]); // error and other length
        } else {
            data.extend_from_slice(&[0, 0, 8, 0]); // SIG type covered=0, algorithm, labels
            data.extend_from_slice(&[0; 12]); // original TTL, expiration, inception
            data.extend_from_slice(&[0, 1, 0]); // key tag and root signer
            data.extend_from_slice(&[0x5a; 32]); // opaque signature
        }
        let additional = u16::from_be_bytes([msg[10], msg[11]]) + 1;
        msg[10..12].copy_from_slice(&additional.to_be_bytes());
        msg.push(0);
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&255u16.to_be_bytes());
        msg.extend_from_slice(&[0; 4]);
        msg.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(&data);
        msg
    }

    #[test]
    fn audit_transaction_signatures_are_never_reusable_cache_entries() {
        for rtype in [250, 24] {
            let signed = with_transaction_signature(response(&[60], true), rtype);
            assert!(dns_message_is_complete(&signed));
            assert_eq!(
                response_cache_ttl(&signed),
                None,
                "type {rtype} is transaction-specific"
            );
        }
    }

    #[test]
    fn audit_large_dns_cache_has_a_byte_budget_not_only_an_entry_count() {
        let mut cache = DnsCacheStore::default();
        for n in 0..1000u32 {
            insert_cache_entry(
                &mut cache,
                n.to_be_bytes().to_vec(),
                vec![0; 40_000],
                Duration::from_secs(60),
                1000,
            );
        }
        let bytes: usize = cache
            .entries
            .iter()
            .map(|(k, (v, _, _))| k.len() + v.len())
            .sum();
        assert!(
            bytes <= 16 * 1024 * 1024,
            "retained {bytes} bytes in {} entries",
            cache.entries.len()
        );
    }

    #[tokio::test]
    async fn audit_multiple_questions_get_formerr_before_upstream_or_blocklist() {
        let mut request = query(None);
        request[5] = 2;
        request.extend_from_within(12..);
        let cfg = Arc::new(DnsConfig {
            upstream: Vec::new(),
            ..serde_json::from_str("{}").unwrap()
        });
        let answer = resolve(
            new_cache(),
            cfg,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request,
        )
        .await;
        let answer = answer.expect("malformed QUERY needs FORMERR, not upstream timeout");
        assert_eq!(answer[3] & 15, 1);
        assert_eq!(answer.len(), 12);
        assert_eq!(&answer[..2], &request[..2]);
    }

    #[tokio::test]
    async fn audit_resolver_ignores_incoming_responses() {
        let request = response(&[60], true);
        let cfg = Arc::new(DnsConfig {
            upstream: Vec::new(),
            ..serde_json::from_str("{}").unwrap()
        });
        assert!(resolve(
            new_cache(),
            cfg,
            Arc::new(AtomicUsize::new(0)),
            compile_blocklist(&["example.com".into()]),
            &request
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn audit_signed_requests_reach_upstream_byte_for_byte() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for rtype in [250, 24] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (sent, received) = tokio::sync::oneshot::channel();
            let request = with_transaction_signature(
                with_opt(query(None), 0, 0, 0, &[0xfd, 0xe8, 0, 1, 42]),
                rtype,
            );
            let mut reply = with_transaction_signature(
                with_opt(response(&[60], true), 0, 0, 0, &[0xfd, 0xe8, 0, 1, 42]),
                rtype,
            );
            reply[..2].copy_from_slice(&request[..2]);
            let expected_reply = reply.clone();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut input = vec![0; usize::from(length)];
                stream.read_exact(&mut input).await.unwrap();
                reply[..2].copy_from_slice(&input[..2]);
                sent.send(input).unwrap();
                stream
                    .write_u16(u16::try_from(reply.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&reply).await.unwrap();
            });
            let _upstream = TestUpstream { address, task };
            let cfg = Arc::new(DnsConfig {
                upstream_protocol: "tcp".into(),
                cache_size: 8,
                timeout_secs: 1,
                ..serde_json::from_str("{}").unwrap()
            });
            let cache: DnsCache = new_cache();
            let answer = resolve_with_upstreams(
                cache.clone(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(HashSet::new()),
                &request,
                &[address],
            )
            .await
            .unwrap();
            assert_eq!(
                received.await.unwrap(),
                request,
                "signed request changed for type {rtype}"
            );
            assert_eq!(answer, expected_reply);
            assert_eq!(cache.read().await.entries.len(), 0);
        }
    }

    fn assert_cache_budget(cache: &DnsCacheStore, entry_limit: usize) {
        let actual: usize = cache
            .entries
            .iter()
            .map(|(key, (value, _, _))| key.len() + value.len())
            .sum();
        assert_eq!(cache.payload_bytes, actual);
        assert!(actual <= MAX_CACHE_PAYLOAD_BYTES);
        assert!(cache.entries.len() <= entry_limit);
    }

    #[test]
    fn cache_accounts_for_large_keys_replacement_and_rejected_entries() {
        let mut cache = DnsCacheStore::default();
        let ttl = Duration::from_secs(60);
        let key = vec![7; MAX_CACHE_PAYLOAD_BYTES - 1];
        insert_cache_entry(&mut cache, key.clone(), vec![1], ttl, 2);
        assert_eq!(cache.payload_bytes, MAX_CACHE_PAYLOAD_BYTES);
        // Oversized replacement must leave the existing usable entry intact.
        insert_cache_entry(&mut cache, key.clone(), vec![1, 2], ttl, 2);
        assert_eq!(cache.entries.get(key.as_slice()).unwrap().0.as_ref(), &[1]);
        insert_cache_entry(&mut cache, key, Vec::new(), ttl, 2);
        assert_eq!(cache.payload_bytes, MAX_CACHE_PAYLOAD_BYTES - 1);
        insert_cache_entry(&mut cache, vec![8], Vec::new(), ttl, 2);
        assert_eq!(cache.entries.len(), 2);
        assert_cache_budget(&cache, 2);
        insert_cache_entry(&mut cache, vec![9], vec![0; 128], ttl, 2);
        assert_cache_budget(&cache, 2);
        assert!(cache.entries.contains_key(&[9][..]));
        let before = (cache.entries.len(), cache.payload_bytes);
        insert_cache_entry(&mut cache, vec![10], vec![1], ttl, 0);
        insert_cache_entry(&mut cache, vec![10], vec![1], Duration::ZERO, 2);
        assert_eq!((cache.entries.len(), cache.payload_bytes), before);
    }

    #[test]
    fn cache_expires_before_eviction_and_honours_small_entry_limits() {
        let mut cache = DnsCacheStore::default();
        let ttl = Duration::from_secs(60);
        insert_cache_entry(&mut cache, vec![1], vec![0; 100], ttl, 2);
        insert_cache_entry(&mut cache, vec![2], vec![0; 100], ttl, 2);
        cache.entries.get_mut(&[1][..]).unwrap().1 = Instant::now() - Duration::from_secs(61);
        insert_cache_entry(&mut cache, vec![3], vec![0; 100], ttl, 2);
        assert!(!cache.entries.contains_key(&[1][..]));
        assert!(cache.entries.contains_key(&[2][..]));
        assert_cache_budget(&cache, 2);
        for limit in [1, 2, 10] {
            for key in 0..64 {
                insert_cache_entry(&mut cache, vec![key], vec![key; 100], ttl, limit);
                assert_cache_budget(&cache, limit);
                assert!(cache.entries.contains_key(&[key][..]));
            }
        }
    }

    #[test]
    fn signature_detection_distinguishes_rrset_signatures_and_rejects_short_sig() {
        for rtype in [24, 46] {
            let mut signed = with_transaction_signature(response(&[60], true), rtype);
            let header = skip_name(&signed, additional_section_start(&signed).unwrap()).unwrap();
            signed[header + 11] = 1; // covers A, not the transaction
            signed[header + 4..header + 8].copy_from_slice(&60u32.to_be_bytes());
            assert_eq!(has_transaction_signature(&signed), Some(false));
            assert_eq!(response_cache_ttl(&signed), Some(Duration::from_secs(60)));
        }
        let mut malformed = with_transaction_signature(response(&[60], true), 24);
        let header = skip_name(&malformed, additional_section_start(&malformed).unwrap()).unwrap();
        malformed[header + 8..header + 10].copy_from_slice(&1u16.to_be_bytes());
        malformed.truncate(header + 11);
        assert_eq!(has_transaction_signature(&malformed), None);
        assert_eq!(response_cache_ttl(&malformed), None);
        for cut in 0..malformed.len() {
            let _ = has_transaction_signature(&malformed[..cut]);
        }
    }

    #[test]
    fn signed_udp_responses_are_unchanged_or_dropped_never_locally_truncated() {
        for rtype in [250, 24] {
            let signed = with_transaction_signature(response(&[60; 40], true), rtype);
            assert!(signed.len() > 512);
            assert_eq!(apply_udp_size_limit(&query(None), signed.clone()), None);
            assert_eq!(
                apply_udp_size_limit(&query(Some(4096)), signed.clone()),
                Some(signed)
            );
        }
    }

    #[tokio::test]
    async fn signed_udp_requests_and_responses_bypass_even_a_preexisting_cache_entry() {
        for rtype in [250, 24] {
            let request = with_transaction_signature(query(None), rtype);
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let mut reply = with_transaction_signature(response(&[60], true), rtype);
            reply[..2].copy_from_slice(&request[..2]);
            let expected_reply = reply.clone();
            let (sent, received) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let mut input = vec![0; 65535];
                let (length, peer) = socket.recv_from(&mut input).await.unwrap();
                input.truncate(length);
                sent.send(input).unwrap();
                socket.send_to(&reply, peer).await.unwrap();
            });
            let _upstream = TestUpstream { address, task };
            let cache = new_cache();
            let mut key = request.clone();
            key[..2].fill(0);
            insert_cache_entry(
                &mut *cache.write().await,
                key.clone(),
                response(&[1234], true),
                Duration::from_secs(60),
                8,
            );
            let cfg = Arc::new(DnsConfig {
                upstream_protocol: "udp".into(),
                timeout_secs: 1,
                ..serde_json::from_str("{}").unwrap()
            });
            let answer = resolve_with_upstreams(
                cache.clone(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(HashSet::new()),
                &request,
                &[address],
            )
            .await
            .unwrap();
            assert_eq!(received.await.unwrap(), request);
            assert_eq!(answer, expected_reply);
            assert_eq!(
                record_min_ttl(&cache.read().await.entries.get(key.as_slice()).unwrap().0),
                Some(1234)
            );
        }
    }

    #[tokio::test]
    async fn unsolicited_transaction_signatures_try_the_next_upstream() {
        for force_tcp in [false, true] {
            for rtype in [250, 24] {
                let signed = with_transaction_signature(response(&[900], true), rtype);
                let first = test_upstream(
                    (!force_tcp).then(|| signed.clone()),
                    force_tcp.then_some(signed),
                )
                .await;
                let good = response(&[60], true);
                let second = test_upstream(
                    (!force_tcp).then(|| good.clone()),
                    force_tcp.then_some(good),
                )
                .await;
                let cfg = Arc::new(DnsConfig {
                    upstream_protocol: if force_tcp { "tcp" } else { "udp" }.into(),
                    timeout_secs: 2,
                    ..serde_json::from_str("{}").unwrap()
                });
                let pref = Arc::new(AtomicUsize::new(0));
                let answer = resolve_with_upstreams(
                    new_cache(),
                    cfg,
                    pref.clone(),
                    Arc::new(HashSet::new()),
                    &query(None),
                    &[first.address, second.address],
                )
                .await
                .unwrap();
                assert_eq!(record_min_ttl(&answer), Some(60));
                assert_eq!(pref.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[tokio::test]
    async fn zero_question_cookie_exchange_is_forwarded() {
        let mut request = query(Some(1232));
        let question_end = question_section_end(&request).unwrap();
        request.drain(12..question_end);
        request[5] = 0;
        // EDNS COOKIE: code=10, length=8, opaque client cookie.
        request[21..23].copy_from_slice(&12u16.to_be_bytes());
        request.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut reply = request.clone();
        reply[2] |= 0x80;
        let upstream = test_upstream(Some(reply.clone()), None).await;
        let cfg = Arc::new(DnsConfig {
            upstream_protocol: "udp".into(),
            timeout_secs: 1,
            ..serde_json::from_str("{}").unwrap()
        });
        let answer = resolve_with_upstreams(
            new_cache(),
            cfg,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request,
            &[upstream.address],
        )
        .await
        .unwrap();
        assert_eq!(answer, reply);
        assert_eq!(response_cache_ttl(&answer), None);
    }

    #[tokio::test]
    async fn unsupported_opcodes_get_notimp_and_never_blocklist_nxdomain() {
        for opcode in [1, 2, 4, 5, 6, 15] {
            let mut request = query(None);
            request[2] = opcode << 3;
            let cfg = Arc::new(DnsConfig {
                upstream: Vec::new(),
                ..serde_json::from_str("{}").unwrap()
            });
            let reply = resolve(
                new_cache(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                compile_blocklist(&["example.com".into()]),
                &request,
            )
            .await
            .unwrap();
            assert_eq!(reply[3] & 15, 4);
            assert_eq!(reply[2] & 0x78, opcode << 3);
            assert_eq!(reply.len(), 12);
        }
    }

    #[tokio::test]
    async fn cache_size_zero_bypasses_existing_entries() {
        let cache = new_cache();
        let request = query(None);
        let mut key = request.clone();
        key[..2].fill(0);
        insert_cache_entry(
            &mut *cache.write().await,
            key,
            response(&[60], true),
            Duration::from_secs(60),
            8,
        );
        let cfg = Arc::new(DnsConfig {
            upstream: Vec::new(),
            cache_size: 0,
            ..serde_json::from_str("{}").unwrap()
        });
        assert!(resolve(
            cache,
            cfg,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(HashSet::new()),
            &request
        )
        .await
        .is_none());
    }

    fn cname_response(ttl: u32) -> Vec<u8> {
        let mut msg = response(&[], false);
        msg[7] = 1;
        msg.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1]);
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&[0, 8, 5, b'a', b'l', b'i', b'a', b's', 0xc0, 0x0c]);
        msg
    }

    #[test]
    fn audit_cname_nodata_cannot_outlive_the_negative_soa() {
        for (alias, soa, minimum, expected) in [
            (300, 120, 5, Some(5)),
            (3, 120, 5, Some(3)),
            (300, 120, 0, None),
        ] {
            let msg = with_soa(cname_response(alias), soa, minimum);
            assert_eq!(response_cache_ttl(&msg), expected.map(Duration::from_secs));
        }
    }

    #[test]
    fn audit_compression_cycles_are_not_complete_dns_messages() {
        let mut msg = response(&[60], true);
        let owner = question_section_end(&msg).unwrap();
        msg[owner..owner + 2].copy_from_slice(&[0xc0, owner as u8]);
        assert!(!dns_message_is_complete(&msg));
        assert_eq!(response_cache_ttl(&msg), None);
    }

    #[test]
    fn audit_dns_names_cannot_expand_beyond_255_bytes() {
        let mut msg = query(None)[..12].to_vec();
        for _ in 0..4 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(!dns_message_is_complete(&msg));
    }

    #[test]
    fn aliases_require_negative_proof_unless_the_requested_rrset_is_present() {
        let alias = cname_response(60);
        assert_eq!(
            response_cache_ttl(&alias),
            None,
            "unresolved A lookup has no negative SOA"
        );
        let mut cname_query = alias.clone();
        let question_end = question_section_end(&alias).unwrap();
        cname_query[question_end - 4..question_end - 2].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(
            response_cache_ttl(&cname_query),
            Some(Duration::from_secs(60))
        );
        let mut resolved = alias;
        resolved[7] = 2;
        resolved.extend_from_slice(&[0xc0, (question_end + 12) as u8, 0, 1, 0, 1]);
        resolved.extend_from_slice(&30u32.to_be_bytes());
        resolved.extend_from_slice(&[0, 4, 192, 0, 2, 80]);
        assert_eq!(response_cache_ttl(&resolved), Some(Duration::from_secs(30)));
    }

    #[test]
    fn name_walker_accepts_boundaries_and_nested_backward_pointers() {
        let mut boundary = query(None)[..12].to_vec();
        for length in [63, 63, 63, 61] {
            boundary.push(length);
            boundary.extend(std::iter::repeat_n(b'a', usize::from(length)));
        }
        boundary.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(dns_message_is_complete(&boundary));
        assert!(first_question_name(&boundary).is_some());
        // 127 one-byte labels plus root is also a legal 255-byte name. Following
        // the answer's compression pointer adds a hop without adding name bytes.
        let mut many_labels = query(None)[..12].to_vec();
        for _ in 0..127 {
            many_labels.extend_from_slice(&[1, b'a']);
        }
        many_labels.extend_from_slice(&[0, 0, 1, 0, 1]);
        many_labels[2] = 0x81;
        many_labels[3] = 0x80;
        many_labels[7] = 1;
        many_labels.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 80]);
        assert_eq!(
            response_cache_ttl(&many_labels),
            Some(Duration::from_secs(60))
        );
        let mut nested = response(&[60, 30], true);
        let first = question_section_end(&nested).unwrap();
        nested[first + 16..first + 18].copy_from_slice(&[0xc0, first as u8]);
        assert!(dns_message_is_complete(&nested));
        assert_eq!(response_cache_ttl(&nested), Some(Duration::from_secs(30)));
        for target in [0, 11, first + 16] {
            let mut bad = nested.clone();
            bad[first..first + 2].copy_from_slice(&[0xc0, target as u8]);
            assert!(!dns_message_is_complete(&bad));
        }
    }

    #[tokio::test]
    async fn cached_queries_age_ttls_restore_ids_and_obey_the_current_blocklist() {
        let cfg = Arc::new(DnsConfig {
            upstream: Vec::new(),
            ..serde_json::from_str("{}").unwrap()
        });
        let cache: DnsCache = new_cache();
        let pref = Arc::new(AtomicUsize::new(0));
        let mut request = query(None);
        request[..2].copy_from_slice(&[0x12, 0x34]);
        let mut key = request.clone();
        key[..2].fill(0);
        insert_cache_entry(
            &mut *cache.write().await,
            key.clone(),
            response(&[60], true),
            Duration::from_secs(60),
            1000,
        );
        cache
            .write()
            .await
            .entries
            .get_mut(key.as_slice())
            .unwrap()
            .1 = Instant::now() - Duration::from_secs(10);
        let hit = resolve(
            cache.clone(),
            cfg.clone(),
            pref.clone(),
            Arc::new(HashSet::new()),
            &request,
        )
        .await
        .unwrap();
        assert_eq!(&hit[..2], &[0x12, 0x34]);
        assert!(record_min_ttl(&hit).is_some_and(|ttl| ttl <= 50));
        let blocked = resolve(
            cache.clone(),
            cfg.clone(),
            pref.clone(),
            compile_blocklist(&["example.com".into()]),
            &request,
        )
        .await
        .unwrap();
        assert_eq!(blocked[3] & 15, 3);
        cache
            .write()
            .await
            .entries
            .get_mut(key.as_slice())
            .unwrap()
            .1 = Instant::now() - Duration::from_secs(61);
        assert!(
            resolve(cache, cfg, pref, Arc::new(HashSet::new()), &request)
                .await
                .is_none()
        );
    }

    struct TestUpstream {
        address: SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestUpstream {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn test_upstream(udp: Option<Vec<u8>>, tcp: Option<Vec<u8>>) -> TestUpstream {
        test_upstream_at("127.0.0.1:0", udp, tcp).await
    }

    async fn test_upstream_at(
        bind: &str,
        udp: Option<Vec<u8>>,
        tcp: Option<Vec<u8>>,
    ) -> TestUpstream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (listener, socket) = crate::dns_test_support::bind_pair(bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            if let Some(mut reply) = udp {
                let mut input = vec![0; 65535];
                let (n, peer) = socket.recv_from(&mut input).await.unwrap();
                assert!(n >= 12);
                reply[..2].copy_from_slice(&input[..2]);
                socket.send_to(&reply, peer).await.unwrap();
            }
            if let Some(mut reply) = tcp {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut input = vec![0; usize::from(length)];
                stream.read_exact(&mut input).await.unwrap();
                reply[..2].copy_from_slice(&input[..2]);
                stream
                    .write_u16(u16::try_from(reply.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&reply).await.unwrap();
            }
        });
        TestUpstream { address, task }
    }

    async fn check_truncated_tcp_failover(force_tcp: bool) {
        let mut truncated = response(&[], true);
        truncated[2] |= 2;
        let first = test_upstream((!force_tcp).then(|| truncated.clone()), Some(truncated)).await;
        let good = response(&[60], true);
        let second = test_upstream(
            (!force_tcp).then(|| good.clone()),
            force_tcp.then_some(good.clone()),
        )
        .await;
        let cfg = Arc::new(DnsConfig {
            upstream_protocol: if force_tcp { "tcp" } else { "udp" }.into(),
            timeout_secs: 2,
            cache_size: 8,
            ..serde_json::from_str("{}").unwrap()
        });
        let cache: DnsCache = new_cache();
        let pref = Arc::new(AtomicUsize::new(0));
        let mut request = query(None);
        request[..2].copy_from_slice(&[0x12, 0x34]);
        let answer = tokio::time::timeout(
            Duration::from_secs(3),
            resolve_with_upstreams(
                cache.clone(),
                cfg,
                pref.clone(),
                Arc::new(HashSet::new()),
                &request,
                &[first.address, second.address],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            answer[2] & 2,
            0,
            "truncated TCP answer must not suppress a healthy fallback"
        );
        assert_eq!(&answer[..2], &[0x12, 0x34]);
        assert_eq!(&answer[2..], &good[2..]);
        assert_eq!(pref.load(Ordering::Relaxed), 1);
        assert_eq!(cache.read().await.entries.len(), 1);
    }

    #[tokio::test]
    async fn audit_forced_tcp_tries_next_upstream_after_tc() {
        check_truncated_tcp_failover(true).await;
    }

    #[tokio::test]
    async fn audit_udp_retry_tries_next_upstream_after_tcp_tc() {
        check_truncated_tcp_failover(false).await;
    }

    #[tokio::test]
    async fn a_silent_preferred_upstream_leaves_time_for_the_fallback() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good = test_upstream(Some(response(&[60], true)), None).await;
        let cfg = Arc::new(DnsConfig {
            timeout_secs: 1,
            upstream_protocol: "udp".into(),
            ..serde_json::from_str("{}").unwrap()
        });
        let cache: DnsCache = new_cache();
        let pref = Arc::new(AtomicUsize::new(0));
        let answer = tokio::time::timeout(
            Duration::from_secs(3),
            resolve_with_upstreams(
                cache,
                cfg,
                pref.clone(),
                Arc::new(HashSet::new()),
                &query(None),
                &[silent.local_addr().unwrap(), good.address],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(answer[7], 1);
        assert_eq!(pref.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_partial_tcp_frame_is_bounded_by_the_exchange_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut input = vec![0; usize::from(length)];
            stream.read_exact(&mut input).await.unwrap();
            stream.write_all(&[0, 20, 0, 0]).await.unwrap();
            std::future::pending::<()>().await;
        });
        let _upstream = TestUpstream { address, task };
        assert!(tokio::time::timeout(
            Duration::from_secs(2),
            query_tcp(
                &address.to_string(),
                &query(None),
                Duration::from_millis(100)
            )
        )
        .await
        .unwrap()
        .is_none());
    }

    /// An upstream reply is only ours if the txid AND the question both match.
    /// (Audit 2026-08-04, M-10.)
    #[test]
    fn response_matches_requires_txid_and_question() {
        let mut query = response(&[], false); // reuse the builder: 1 question, no answers
        query[2] = 0x01; // a query, not a response (RD set, QR clear)
        query[3] = 0x00;
        let good = response(&[300], false);
        let txid = [0xAB, 0xCD];

        assert!(
            response_matches(&good, txid, &query),
            "the real answer must pass"
        );

        // Wrong transaction ID.
        let mut wrong_txid = good.clone();
        wrong_txid[0] = 0x00;
        assert!(!response_matches(&wrong_txid, txid, &query));
        let mut wrong_opcode = good.clone();
        wrong_opcode[2] |= 0x28; // UPDATE reply cannot satisfy an ordinary QUERY.
        assert!(!response_matches(&wrong_opcode, txid, &query));

        // Right txid, DIFFERENT question — the birthday-spray case the question match
        // exists to stop.
        let mut other = good.clone();
        other[13] = b'X'; // "example" -> "Xxample"
        assert!(!response_matches(&other, txid, &query));

        // Right txid and question, but QR clear — a reflected query, not an answer.
        let mut reflected = good.clone();
        reflected[2] &= 0x7F;
        assert!(!response_matches(&reflected, txid, &query));

        // Truncated to the header, and to nothing.
        assert!(!response_matches(&good[..11], txid, &query));
        assert!(!response_matches(&[], txid, &query));

        // A reply claiming a different QDCOUNT must not pass.
        let mut qd = good.clone();
        qd[5] = 2;
        assert!(!response_matches(&qd, txid, &query));
    }

    #[test]
    fn blocklist_matching_is_bounded_and_nxdomain_strips_request_records() {
        let q = query(Some(1232));
        let exact = compile_blocklist(&["EXAMPLE.COM.".to_string()]);
        assert!(is_blocked(&q, &exact));
        let not_a_label_suffix = compile_blocklist(&["ample.com".to_string()]);
        assert!(!is_blocked(&q, &not_a_label_suffix));

        // A compression loop is untrusted input, not a name to keep decoding forever.
        let mut looped = q.clone();
        looped[12..14].copy_from_slice(&[0xC0, 0x0C]);
        assert!(!is_blocked(&looped, &exact));

        // Even if the client supplied resource records, a synthetic NXDOMAIN carries only
        // the validated question. Reflecting those bytes as part of our answer would produce
        // contradictory counts and replay attacker-controlled payload.
        let mut with_answer = response(&[60], true);
        with_answer[2] &= 0x7F; // make it a request-shaped message
        let q_end = question_section_end(&with_answer).unwrap();
        let blocked = blocked_response(&with_answer).unwrap();
        assert_eq!(blocked.len(), q_end);
        assert_eq!(&blocked[12..], &with_answer[12..q_end]);
        assert_eq!(blocked[2] & 0x80, 0x80);
        assert_eq!(blocked[3] & 0x0F, 3);
        assert_eq!(&blocked[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    /// Build a minimal DNS response: one question, `answers` A-records with the given TTLs.
    fn response(ttls: &[u32], compressed_names: bool) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0] = 0xAB;
        m[1] = 0xCD; // txid
        m[2] = 0x81;
        m[3] = 0x80; // response, no error
        m[4] = 0;
        m[5] = 1; // QDCOUNT = 1
        m[6] = 0;
        m[7] = ttls.len() as u8; // ANCOUNT
                                 // Question: "example.com" A IN
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        for ttl in ttls {
            if compressed_names {
                m.extend_from_slice(&[0xC0, 0x0C]); // pointer back to the question name
            } else {
                m.extend_from_slice(&[7]);
                m.extend_from_slice(b"example");
                m.extend_from_slice(&[3]);
                m.extend_from_slice(b"com");
                m.push(0);
            }
            m.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A, CLASS=IN
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]); // RDLENGTH
            m.extend_from_slice(&[93, 184, 216, 34]); // RDATA
        }
        m
    }

    fn with_soa(mut m: Vec<u8>, soa_ttl: u32, minimum: u32) -> Vec<u8> {
        m[9] = 1; // NSCOUNT = 1
        m.extend_from_slice(&[0xC0, 0x0C]); // owner = question name
        m.extend_from_slice(&[0, 6, 0, 1]); // TYPE=SOA, CLASS=IN
        m.extend_from_slice(&soa_ttl.to_be_bytes());
        m.extend_from_slice(&22u16.to_be_bytes());
        m.push(0); // MNAME = root
        m.push(0); // RNAME = root
        for value in [1, 3600, 600, 86_400, minimum] {
            m.extend_from_slice(&value.to_be_bytes());
        }
        m
    }

    fn negative_response(rcode: u8, soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut m = response(&[], false);
        m[3] = (m[3] & 0xF0) | (rcode & 0x0F);
        with_soa(m, soa_ttl, minimum)
    }

    #[test]
    fn reads_the_smallest_record_ttl() {
        assert_eq!(record_min_ttl(&response(&[300], false)), Some(300));
        assert_eq!(record_min_ttl(&response(&[300, 60, 900], false)), Some(60));
    }

    #[test]
    fn cache_admission_honours_short_ttls_and_rejects_tc() {
        assert_eq!(
            response_cache_ttl(&response(&[1], false)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            response_cache_ttl(&response(&[4], false)),
            Some(Duration::from_secs(4))
        );
        assert_eq!(response_cache_ttl(&response(&[0], false)), None);
        let mut truncated = response(&[60], false);
        truncated[2] |= 0x02;
        assert_eq!(response_cache_ttl(&truncated), None);

        let mut malformed_positive = response(&[60], false);
        malformed_positive.truncate(malformed_positive.len() - 1);
        assert_eq!(response_cache_ttl(&malformed_positive), None);

        let no_answers = response(&[], false);
        assert_eq!(response_cache_ttl(&no_answers), None);
        let mut nxdomain = no_answers.clone();
        nxdomain[3] = (nxdomain[3] & 0xF0) | 3;
        assert_eq!(response_cache_ttl(&nxdomain), None);
        assert_eq!(
            response_cache_ttl(&negative_response(3, 300, 45)),
            Some(Duration::from_secs(45)),
            "negative TTL is min(SOA RR TTL, SOA.MINIMUM)"
        );
        assert_eq!(
            response_cache_ttl(&negative_response(0, 20, 300)),
            Some(Duration::from_secs(20)),
            "NODATA uses the same RFC 2308 SOA lifetime"
        );
        let mut cname_nxdomain = response(&[300], true);
        cname_nxdomain[3] = (cname_nxdomain[3] & 0xF0) | 3;
        assert_eq!(
            response_cache_ttl(&with_soa(cname_nxdomain, 120, 45)),
            Some(Duration::from_secs(45)),
            "NXDOMAIN with a CNAME cannot outlive its negative SOA TTL"
        );
        assert_eq!(response_cache_ttl(&negative_response(3, 300, 0)), None);
        for rcode in [1, 2, 5] {
            let mut error = no_answers.clone();
            error[3] = (error[3] & 0xF0) | rcode;
            assert!(response_is_retryable_error(&error));
            assert_eq!(
                response_cache_ttl(&error),
                None,
                "DNS error rcode {rcode} must not be cached"
            );
        }
        assert!(!response_is_retryable_error(&nxdomain));
        let mut trailing_garbage = response(&[60], false);
        trailing_garbage.push(0);
        assert_eq!(response_cache_ttl(&trailing_garbage), None);

        let mut badvers = query(Some(1232));
        badvers[2] = 0x81;
        badvers[3] = 0x80;
        let opt = additional_section_start(&badvers).unwrap();
        let after_name = skip_name(&badvers, opt).unwrap();
        badvers[after_name + 4] = 1; // extended RCODE 1 => BADVERS (full RCODE 16)
        assert!(response_is_retryable_error(&badvers));
        assert_eq!(response_cache_ttl(&badvers), None);
    }

    #[test]
    fn follows_compressed_names() {
        // The common real-world shape: answers point back at the question's name.
        assert_eq!(record_min_ttl(&response(&[120, 45], true)), Some(45));
    }

    #[test]
    fn no_records_yields_none() {
        // NXDOMAIN / NODATA — nothing to derive a lifetime from.
        assert_eq!(record_min_ttl(&response(&[], false)), None);
    }

    #[test]
    fn malformed_input_never_panics() {
        // Truncated at every possible length: each must be rejected, not crash.
        let full = response(&[300, 60], true);
        for cut in 0..full.len() {
            let _ = record_min_ttl(&full[..cut]);
        }
        // Header claims answers that are not there.
        let mut lying = response(&[300], false);
        lying[7] = 200;
        assert_eq!(record_min_ttl(&lying), None);
        // A name length that runs past the buffer.
        let mut runaway = response(&[300], false);
        let qname = 12;
        runaway[qname] = 0xFF;
        assert_eq!(record_min_ttl(&runaway), None);
        // A compression pointer loop must terminate without panicking.
        let mut looped = response(&[300], true);
        looped[12] = 0xC0;
        looped[13] = 0x0C;
        let _ = record_min_ttl(&looped);
        assert_eq!(record_min_ttl(&[]), None);
        assert_eq!(record_min_ttl(&[0u8; 11]), None);
    }

    #[test]
    fn ttl_zero_is_distinguishable() {
        // Some(0) must survive to the caller so it can skip caching entirely.
        assert_eq!(record_min_ttl(&response(&[0], false)), Some(0));
    }

    /// A query with no OPT record, and one advertising `payload` bytes via EDNS0.
    fn query(payload: Option<u16>) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0] = 0xAB;
        m[1] = 0xCD;
        m[5] = 1; // QDCOUNT = 1
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        if let Some(size) = payload {
            m[11] = 1; // ARCOUNT = 1
            m.push(0); // OPT NAME = root
            m.extend_from_slice(&[0, 41]); // TYPE = OPT (41)
            m.extend_from_slice(&size.to_be_bytes()); // CLASS carries the payload size
            m.extend_from_slice(&[0, 0, 0, 0]); // TTL (extended rcode + flags)
            m.extend_from_slice(&[0, 0]); // RDLENGTH
        }
        m
    }

    /// The size a client says it can take governs whether the answer is truncated, and RFC 1035
    /// §4.2.1's 512 is the floor when it says nothing at all.
    #[test]
    fn the_advertised_udp_size_comes_from_the_opt_record() {
        assert_eq!(advertised_udp_size(&query(None)), 512);
        assert_eq!(advertised_udp_size(&query(Some(1232))), 1232);
        // Clamped at both ends: a peer may advertise anything, and a UDP datagram cannot
        // exceed 65535 however large a number it writes.
        assert_eq!(advertised_udp_size(&query(Some(128))), 512);
        assert_eq!(advertised_udp_size(&query(Some(65535))), 65_535);

        // The receive buffer follows the advertisement, because `recv_from` silently discards
        // whatever does not fit — a client that asked for 8192 used to have its answer chopped
        // at 4096 and forwarded malformed. The floor keeps the common case unchanged.
        assert_eq!(upstream_buf_size(&query(None)), 4096);
        assert_eq!(upstream_buf_size(&query(Some(1232))), 4096);
        assert_eq!(upstream_buf_size(&query(Some(8192))), 8192);
        assert_eq!(upstream_buf_size(&query(Some(65535))), 65_535);
        // Malformed input falls back to the floor rather than panicking.
        let full = query(Some(4096));
        for cut in 0..full.len() {
            let _ = advertised_udp_size(&full[..cut]);
        }
        let mut truncated_opt = full;
        let opt = additional_section_start(&truncated_opt).unwrap();
        let after_name = skip_name(&truncated_opt, opt).unwrap();
        truncated_opt[after_name + 8..after_name + 10].copy_from_slice(&4u16.to_be_bytes());
        truncated_opt.extend_from_slice(&[1, 2, 3]); // one byte short of the declared RDATA
        assert_eq!(advertised_udp_size(&truncated_opt), 512);
    }

    /// An answer that fits is forwarded untouched; one that does not comes back as a TC=1
    /// header plus the question, NOT as the original bytes cut short.
    ///
    /// Chopping mid-record would leave the counts promising records that are not present, which
    /// a resolver reads as a malformed message rather than as "retry over TCP" — and retrying
    /// over TCP is the whole point, now that there is a TCP listener to retry against.
    /// (Audit 2026-08-01, §10.)
    #[test]
    fn an_oversized_answer_is_truncated_with_tc_set() {
        let q = query(Some(512));
        // Fits: byte-for-byte the same object comes back.
        let small = response(&[300], true);
        assert!(small.len() <= 512);
        assert_eq!(apply_udp_size_limit(&q, small.clone()).unwrap(), small);

        // Does not fit: 40 A-records is well past 512 bytes.
        let big = response(&[300; 40], true);
        assert!(big.len() > 512);
        let out = apply_udp_size_limit(&q, big).unwrap();
        assert!(
            out.len() <= 512,
            "the reply must fit what the client advertised"
        );
        assert_eq!(&out[0..2], &q[0..2], "the txid must match the query");
        assert_eq!(out[2] & 0x80, 0x80, "QR must say this is a response");
        assert_eq!(out[2] & 0x02, 0x02, "TC must be set");
        assert_eq!(out[3] & 0x0F, 0, "a NOERROR answer stays NOERROR");
        assert_eq!(
            u16::from_be_bytes([out[4], out[5]]),
            1,
            "the question is carried, so QDCOUNT stays 1"
        );
        for (label, off) in [("ANCOUNT", 6), ("NSCOUNT", 8)] {
            assert_eq!(
                u16::from_be_bytes([out[off], out[off + 1]]),
                0,
                "{label} must be zero — no records are carried"
            );
        }
        // The question section itself survives intact, so a resolver can match the reply.
        let question_end = question_section_end(&q).unwrap();
        assert_eq!(&out[12..question_end], &q[12..question_end]);
        assert_eq!(out[11], 1, "EDNS metadata survives truncation");
        assert!(edns(&out).unwrap().is_some());

        // A client that advertised room for it gets the whole thing instead.
        let big = response(&[300; 40], true);
        let roomy = query(Some(4096));
        assert!(big.len() <= 4096);
        assert_eq!(apply_udp_size_limit(&roomy, big.clone()).unwrap(), big);
    }

    /// The truncated reply must carry the ANSWER's flags, not the query's.
    ///
    /// They were rebuilt from the query with RCODE forced to NOERROR, so an oversized NXDOMAIN
    /// went out as NOERROR+TC and RA/AA/AD were lost with it — a stub that reads the truncated
    /// header before deciding whether the TCP retry is worth it was told the wrong thing.
    /// (Audit 2026-08-01, §10.)
    #[test]
    fn a_truncated_reply_keeps_the_answers_rcode_and_flags() {
        let q = query(Some(512));
        let mut big = response(&[300; 40], true);
        assert!(big.len() > 512);
        big[2] = 0x85; // QR + AA + RD
        big[3] = 0x83; // RA + NXDOMAIN (rcode 3)

        let out = apply_udp_size_limit(&q, big).unwrap();
        assert_eq!(out[3] & 0x0F, 3, "NXDOMAIN must survive truncation");
        assert_eq!(out[3] & 0x80, 0x80, "RA must survive");
        assert_eq!(out[2] & 0x04, 0x04, "AA must survive");
        assert_eq!(out[2] & 0x80, 0x80, "QR is forced — this IS a response");
        assert_eq!(out[2] & 0x02, 0x02, "TC must be set");
    }

    /// A cached answer must be served with the REMAINING lifetime.
    ///
    /// Only the transaction ID used to be rewritten, so a reply served a second before its
    /// cache entry expired still claimed the full original TTL — and every layer that caches
    /// on that number compounds the staleness (RFC 2181 §5.2). The OPT pseudo-record is the
    /// exception: its "TTL" is the extended RCODE and flags, so ageing it would corrupt the
    /// answer rather than expire it. (Audit 2026-08-01, §10.)
    #[test]
    fn cached_answers_are_served_with_the_remaining_ttl() {
        fn ttls_of(msg: &[u8]) -> Vec<u32> {
            let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
            let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
            let mut pos = 12;
            for _ in 0..qd {
                pos = skip_name(msg, pos).unwrap() + 4;
            }
            let mut out = Vec::new();
            for _ in 0..an {
                let p = skip_name(msg, pos).unwrap();
                out.push(u32::from_be_bytes([
                    msg[p + 4],
                    msg[p + 5],
                    msg[p + 6],
                    msg[p + 7],
                ]));
                pos = p + 10 + u16::from_be_bytes([msg[p + 8], msg[p + 9]]) as usize;
            }
            out
        }

        let mut msg = response(&[300, 60], true);
        decrement_ttls(&mut msg, 45);
        assert_eq!(
            ttls_of(&msg),
            vec![255, 15],
            "TTLs must age by the time cached"
        );

        // Saturating, never wrapping: an entry older than its record reads as 0, not as ~4e9.
        let mut expired = response(&[10], true);
        decrement_ttls(&mut expired, 5_000);
        assert_eq!(ttls_of(&expired), vec![0]);

        // Zero age is a no-op, and a malformed message must not panic.
        let untouched = response(&[300], true);
        let mut same = untouched.clone();
        decrement_ttls(&mut same, 0);
        assert_eq!(same, untouched);
        for cut in 0..untouched.len() {
            let mut t = untouched[..cut].to_vec();
            decrement_ttls(&mut t, 10);
        }

        // An OPT record's TTL field carries the extended RCODE and flags — ageing it would
        // corrupt the answer. Append one and check it comes back byte-for-byte.
        let mut with_opt = response(&[300], true);
        with_opt[11] = 1; // ARCOUNT = 1
        let opt_at = with_opt.len();
        // NAME(1: root) TYPE(2: 41) CLASS(2: 4096 payload) TTL(4: ext-rcode+flags) RDLEN(2)
        with_opt.extend_from_slice(&[0, 0, 41, 0x10, 0, 0x80, 0, 0, 0, 0, 0]);
        decrement_ttls(&mut with_opt, 100);
        assert_eq!(
            &with_opt[opt_at + 5..opt_at + 9],
            &[0x80, 0, 0, 0],
            "the OPT record's flags must not be decremented"
        );
    }
    #[tokio::test]
    async fn profile_shutdown_releases_pending_upstream_socket() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let tasks = crate::profile_tasks::ProfileTasks::new("pending-upstream");
        tasks.spawn(async move {
            let cfg = Arc::new(DnsConfig {
                upstream_protocol: "udp".into(),
                timeout_secs: 30,
                ..Default::default()
            });
            let _ = resolve_with_upstreams(
                new_cache(),
                cfg,
                Arc::new(AtomicUsize::new(0)),
                compile_blocklist(&[]),
                &query(None),
                &[addr],
            )
            .await;
        });
        let mut buf = [0; 512];
        let (_, source) =
            tokio::time::timeout(Duration::from_secs(5), upstream.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        // Match the resolver's wildcard bind. Some hosts allow a specific-address bind
        // alongside a wildcard UDP socket, so binding `source` would not test ownership.
        let wildcard = SocketAddr::from(([0, 0, 0, 0], source.port()));
        assert!(
            UdpSocket::bind(wildcard).await.is_err(),
            "query must own its upstream socket"
        );
        tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
            .await
            .unwrap()
            .unwrap();
        let _rebound = UdpSocket::bind(wildcard)
            .await
            .expect("upstream socket leaked after shutdown");
    }
}
