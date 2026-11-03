"""Pure measurement admission shared by the lab runner and offline reports."""

import ipaddress
import math
import re


def parse_ping_latency(raw, expected_packets):
    """Linux iputils RTT population; lost probes are reported, never imputed."""
    if not isinstance(raw, str) or type(expected_packets) is not int or expected_packets <= 0:
        raise ValueError('invalid requested ping population')
    summaries = re.findall(r'^([0-9]+) packets transmitted, ([0-9]+) received, ([0-9.]+)% packet loss,', raw, re.M)
    if len(summaries) != 1:
        raise ValueError('ping summary missing or ambiguous')
    sent, received, loss = summaries[0]
    sent, received, loss = int(sent), int(received), float(loss)
    if sent != expected_packets or not 0 < received <= sent or not math.isfinite(loss):
        raise ValueError('ping population truncated or invalid')
    actual_loss = 100 * (sent - received) / sent
    # iputils rounds the printed loss to its display precision.
    if abs(actual_loss - loss) > .051:
        raise ValueError('ping loss disagrees with population')
    replies = []
    for line in raw.splitlines():
        if 'icmp_seq=' not in line:
            continue
        match = re.fullmatch(r'\[([0-9]+\.[0-9]+)\] [0-9]+ bytes from .+: icmp_seq=([0-9]+) ttl=[0-9]+ time=([0-9]+(?:\.[0-9]+)?) ms', line)
        if not match:
            raise ValueError('unsupported or censored ping reply')
        epoch, sequence, rtt = float(match[1]), int(match[2]), float(match[3])
        if not math.isfinite(epoch) or not math.isfinite(rtt) or not 1 <= sequence <= sent:
            raise ValueError('invalid ping reply')
        replies.append(dict(epoch=epoch, sequence=sequence, rtt_ms=rtt))
    if len(replies) != received or len({r['sequence'] for r in replies}) != received:
        raise ValueError('ping replies missing or duplicated')
    ordered = sorted(r['rtt_ms'] for r in replies)
    return dict(transmitted=sent, received=received, lost=sent-received,
                lost_percent=actual_loss, percentile_method='nearest-rank',
                p50_ms=ordered[math.ceil(.50*received)-1],
                p95_ms=ordered[math.ceil(.95*received)-1],
                p99_ms=ordered[math.ceil(.99*received)-1],
                min_ms=ordered[0], max_ms=ordered[-1], replies=replies)


def measurement_phases(profile, transport):
    if transport not in ('direct', 'tcp', 'udp'):
        raise ValueError('unsupported measurement transport')
    if profile == 'tcp-bidir':
        return ('tcp_bidir',)
    if profile == 'udp-bidir':
        return ('udp_bidir',)
    if profile != 'standard' or transport not in ('direct', 'tcp', 'udp'):
        raise ValueError('unsupported measurement profile or transport')
    if transport == 'direct':
        return ('tcp_up', 'tcp_down', 'udp_500')
    return ('tcp_up', 'tcp_down', 'udp_100', 'udp_500') if transport == 'udp' else ('tcp_up', 'tcp_down')


def bidir_counter_deltas(before, after):
    result = counter_deltas(before, after)
    client = counter_deltas(dict(application=before['application'], kernel=before['client_kernel']),
                            dict(application=after['application'], kernel=after['client_kernel']))
    return dict(server_session_drops=result['server_session_drops'],
                server_kernel_rcvbuf_drops=result['kernel_rcvbuf_drops'],
                client_kernel_rcvbuf_drops=client['kernel_rcvbuf_drops'])


def counter_deltas(before, after):
    families = ('ipv4', 'ipv6')
    dual = any(any(key in snapshot['kernel'] for key in families) for snapshot in (before, after))
    for snapshot in (before, after):
        app, kernel = snapshot['application'], snapshot['kernel']
        for key in ('dropped', 'bytes_sent', 'bytes_recv', 'connected_secs'):
            if type(app[key]) is not int or app[key] < 0:
                raise ValueError('invalid application counter')
        if type(kernel['RcvbufErrors']) is not int or kernel['RcvbufErrors'] < 0:
            raise ValueError('invalid kernel drop counter')
        if dual:
            for family in families:
                value = kernel.get(family)
                if not isinstance(value, dict) or type(value.get('RcvbufErrors')) is not int or value['RcvbufErrors'] < 0:
                    raise ValueError('kernel family drop counter missing or invalid')
            if kernel['RcvbufErrors'] != sum(kernel[family]['RcvbufErrors'] for family in families):
                raise ValueError('kernel drop total disagrees with families')
        if any(not isinstance(app[key], str) or not app[key] for key in ('ip', 'peer')):
            raise ValueError('benchmark session identity missing')
    if any(before['application'][key] != after['application'][key] for key in ('ip', 'peer')):
        raise ValueError('benchmark session identity changed')
    if any(after['application'][key] < before['application'][key] for key in ('dropped', 'bytes_sent', 'bytes_recv', 'connected_secs')):
        raise ValueError('benchmark session counters reset')
    if after['kernel']['RcvbufErrors'] < before['kernel']['RcvbufErrors']:
        raise ValueError('benchmark kernel counter reset')
    if dual and any(after['kernel'][family]['RcvbufErrors'] < before['kernel'][family]['RcvbufErrors'] for family in families):
        raise ValueError('benchmark kernel family counter reset')
    return dict(kernel_rcvbuf_drops=after['kernel']['RcvbufErrors'] - before['kernel']['RcvbufErrors'],
                server_session_drops=after['application']['dropped'] - before['application']['dropped'])


def parse_iperf_result(raw, protocol, expected_seconds):
    """Require a completed receiver measurement, never a sender-only fallback."""
    if not isinstance(raw, dict) or 'error' in raw:
        raise ValueError('iperf error or invalid JSON result')
    end = raw.get('end')
    if not isinstance(end, dict) or not isinstance(end.get('sum_received'), dict):
        raise ValueError('iperf receiver summary missing')
    received = end['sum_received']

    def number(source, key, minimum=0, maximum=None):
        value = source.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
            raise ValueError('invalid iperf ' + key)
        return value

    if number(received, 'seconds') < expected_seconds * .9:
        raise ValueError('iperf receiver interval truncated')
    number(received, 'bytes')
    mbps = number(received, 'bits_per_second') / 1e6
    if protocol == 'tcp':
        sent = end.get('sum_sent')
        if not isinstance(sent, dict) or type(sent.get('retransmits')) is not int or sent['retransmits'] < 0:
            raise ValueError('iperf TCP retransmits missing or invalid')
        return dict(mbps=mbps, retransmits=sent['retransmits'], lost_percent=None, jitter_ms=None)
    if protocol == 'udp':
        return dict(mbps=mbps, retransmits=None,
                    lost_percent=number(received, 'lost_percent', maximum=100),
                    jitter_ms=number(received, 'jitter_ms'))
    raise ValueError('unsupported iperf protocol')


def validate_iperf_tcp_bidir_roles(raw, parallel):
    """Match stream endpoints, not accept order: each connection needs one TX and one RX."""
    def endpoint(connection):
        values = []
        for side in ('local', 'remote'):
            try:
                host = connection[side + '_host']
                if not isinstance(host, str):
                    raise ValueError('stream host must be an IP literal')
                address = ipaddress.ip_address(host)
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError('iperf bidir stream address missing or invalid') from error
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            port = connection.get(side + '_port')
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('iperf bidir stream port missing or invalid')
            values.append((str(address), port))
        return tuple(values)

    def streams(result):
        if not isinstance(result, dict):
            raise ValueError('iperf bidir endpoint output missing')
        start, end = result.get('start'), result.get('end')
        connected = start.get('connected') if isinstance(start, dict) else None
        records = end.get('streams') if isinstance(end, dict) else None
        if not isinstance(connected, list) or not isinstance(records, list) or len(connected) != 2 * parallel or len(records) != 2 * parallel:
            raise ValueError('iperf bidir endpoint streams missing or incomplete')
        roles = {}
        for record in records:
            sender = record.get('sender') if isinstance(record, dict) else None
            sock = sender.get('socket') if isinstance(sender, dict) else None
            role = sender.get('sender') if isinstance(sender, dict) else None
            if type(sock) is not int or sock < 0 or sock in roles or type(role) is not bool:
                raise ValueError('iperf bidir endpoint role missing or ambiguous')
            roles[sock] = role
        if sum(roles.values()) != parallel:
            raise ValueError('iperf bidir endpoint direction count disagrees')
        result = {}
        seen_sockets = set()
        for connection in connected:
            if not isinstance(connection, dict):
                raise ValueError('iperf bidir endpoint connection invalid')
            sock = connection.get('socket')
            if type(sock) is not int or sock not in roles or sock in seen_sockets:
                raise ValueError('iperf bidir connection socket missing or ambiguous')
            key = endpoint(connection)
            if key in result:
                raise ValueError('iperf bidir endpoint connection duplicated')
            seen_sockets.add(sock)
            result[key] = dict(socket=sock, sender=roles[sock])
        return result

    if type(parallel) is not int or parallel <= 0:
        raise ValueError('invalid requested bidir stream count')
    client = streams(raw)
    if 'server_output_json' in raw:
        server = streams(raw['server_output_json'])
    else:
        output = raw.get('server_output_text')
        if not isinstance(output, str) or not output or len(output) > 1048576:
            raise ValueError('iperf TCP bidir server role evidence missing or invalid')
        roles = {}
        for sock, role in re.findall(r'^\s*\[\s*(\d+)\]\[(RX-S|TX-S)\]', output, re.M):
            sock, sender = int(sock), role == 'TX-S'
            if sock in roles and roles[sock] != sender:
                raise ValueError('iperf bidir server role ambiguous')
            roles[sock] = sender
        connections = re.findall(r'^\s*\[\s*(\d+)\] local (\S+) port (\d+) connected to (\S+) port (\d+)\s*$', output, re.M)
        server = {}
        for sock, local, local_port, remote, remote_port in connections:
            sock = int(sock)
            if sock not in roles:
                raise ValueError('iperf bidir server stream role missing')
            key = endpoint(dict(local_host=local, local_port=int(local_port), remote_host=remote, remote_port=int(remote_port)))
            if key in server or any(x['socket'] == sock for x in server.values()):
                raise ValueError('iperf bidir server stream duplicated')
            server[key] = dict(socket=sock, sender=roles[sock])
        if len(server) != 2 * parallel or len(roles) != 2 * parallel or sum(x['sender'] for x in server.values()) != parallel:
            raise ValueError('iperf bidir server streams missing or incomplete')
    if set(server) != {(remote, local) for local, remote in client}:
        raise ValueError('iperf bidir client/server endpoints disagree')
    receipt = []
    for (local, remote), stream in client.items():
        peer = server[(remote, local)]
        if stream['sender'] == peer['sender']:
            raise ValueError('iperf TCP bidir endpoint roles conflict (TX/TX or RX/RX)')
        receipt.append(dict(client_endpoint=local, server_endpoint=remote,
                            client_socket=stream['socket'], server_socket=peer['socket'],
                            client_sender=stream['sender'], server_sender=peer['sender']))
    return receipt


def parse_iperf_bidir(raw, expected_seconds, parallel, *, expected_bitrate=0, protocol='tcp', expected_block_size=1200, require_tcp_roles=False):
    """Require both receiver directions; TCP and UDP use different sender flags."""
    if (protocol not in ('tcp', 'udp') or type(expected_seconds) is not int or expected_seconds <= 0
            or type(parallel) is not int or parallel <= 0 or type(require_tcp_roles) is not bool):
        raise ValueError('invalid requested bidir settings')
    if not isinstance(raw, dict) or 'error' in raw:
        raise ValueError('iperf error or invalid JSON result')
    start = raw.get('start')
    if not isinstance(start, dict) or not isinstance(start.get('test_start'), dict):
        raise ValueError('iperf bidir start settings missing')
    if type(expected_bitrate) is not int or expected_bitrate < 0:
        raise ValueError('invalid requested bidir bitrate')
    # iperf3 reports this twice. A paced diagnostic must never silently enter
    # the ordinary unlimited-throughput population (nor the reverse).
    for settings in (start, start['test_start']):
        if type(settings.get('target_bitrate')) is not int or settings['target_bitrate'] != expected_bitrate:
            raise ValueError('iperf bidir bitrate disagrees with requested phase')
    start = start['test_start']
    if (start.get('protocol') != protocol.upper() or type(start.get('bidir')) is not int or start['bidir'] != 1
            or start.get('reverse') != 0 or type(start.get('num_streams')) is not int
            or start['num_streams'] != parallel or start.get('duration') != expected_seconds):
        raise ValueError('iperf bidir settings disagree with requested phase')
    if protocol == 'tcp' and (require_tcp_roles or 'server_output_json' in raw or 'server_output_text' in raw):
        validate_iperf_tcp_bidir_roles(raw, parallel)
    if protocol == 'udp' and (type(expected_block_size) is not int or expected_block_size <= 0
                             or type(start.get('blksize')) is not int or start['blksize'] != expected_block_size):
        raise ValueError('iperf UDP datagram size disagrees with requested phase')
    end = raw.get('end')
    if not isinstance(end, dict):
        raise ValueError('iperf bidir receiver summary missing')
    metrics = {}
    for direction, suffix, sender in (('up', '', True), ('down', '_bidir_reverse', False)):
        received, sent = end.get('sum_received' + suffix), end.get('sum_sent' + suffix)
        received_sender = sender if protocol == 'tcp' else False
        sent_sender = sender if protocol == 'tcp' else True
        if not isinstance(received, dict) or not isinstance(sent, dict) or received.get('sender') is not received_sender or sent.get('sender') is not sent_sender:
            raise ValueError('iperf bidir direction or receiver summary missing')
        sent_seconds = sent.get('seconds')
        if type(sent_seconds) not in (int, float) or not math.isfinite(sent_seconds) or sent_seconds < expected_seconds * .9:
            raise ValueError('iperf bidir sender interval truncated or invalid')
        # Reuse the same admission rules for goodput, duration and retransmits.
        result = parse_iperf_result(dict(end=dict(sum_received=received, sum_sent=sent)), protocol, expected_seconds)
        if result['mbps'] <= 0 or received['bytes'] <= 0:
            raise ValueError('iperf bidir receiver made no progress')
        keys = ('mbps', 'retransmits') if protocol == 'tcp' else ('mbps', 'lost_percent', 'jitter_ms')
        metrics.update({direction + '_' + key: result[key] for key in keys})
        if protocol == 'udp':
            for source, key in ((received, 'packets'), (received, 'lost_packets'), (sent, 'packets')):
                if type(source.get(key)) is not int or source[key] < 0:
                    raise ValueError('invalid iperf UDP packet counter')
            packets, lost = received['packets'], received['lost_packets']
            if not packets or not sent['packets'] or lost > packets or lost > sent['packets']:
                raise ValueError('invalid iperf UDP packet population')
            # iperf3 3.18 computes the JSON loss against sender_total_packets,
            # then emits receiver_total_packets in sum_received.packets.
            # These can differ, especially in reverse UDP under load.
            if not math.isclose(result['lost_percent'], 100 * lost / sent['packets'], rel_tol=1e-9, abs_tol=1e-9):
                raise ValueError('iperf UDP loss disagrees with packet population')
            metrics.update({direction + '_packets': packets, direction + '_lost_packets': lost,
                            direction + '_sent_packets': sent['packets']})
    return metrics
