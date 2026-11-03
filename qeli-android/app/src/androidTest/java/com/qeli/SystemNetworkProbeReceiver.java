package com.qeli;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Process;
import android.os.CancellationSignal;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.DnsResolver;
import android.net.LinkProperties;
import android.net.LinkAddress;
import android.net.NetworkCapabilities;
import java.util.List;
import java.io.FileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import android.util.Log;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Standalone test APK process: platform Java only, ordinary UID traffic without bind/protect. */
public final class SystemNetworkProbeReceiver extends BroadcastReceiver {
    private static volatile File journal;
    private static synchronized void record(String message) {
        // Only test-APK data. Read by the lab for evidence; socket UID is unchanged.
        try (FileOutputStream output = new FileOutputStream(journal, true)) {
            output.write((message + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (Exception error) { Log.e("Q29Probe", "JOURNAL_FAIL", error); }
        Log.i("Q29Probe", message);
    }
    private static String sha(byte[] data) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(data)) hex.append(String.format("%02x", value & 255));
        return hex.toString();
    }
    @Override public void onReceive(Context context, Intent intent) {
        journal = new File(context.getFilesDir(), "q29-probes.log");
        final String tag = intent.getStringExtra("tag");
        if (!"Q29BASELINE".equals(tag) && !"Q29PROTECTED".equals(tag) && !"Q29BLOCKED".equals(tag) && !"Q29DEAD".equals(tag) && !"Q29RECOVERED".equals(tag) && !"Q29MANUAL".equals(tag)) return;
        if (intent.hasExtra("dns_name")) {
            final String name = intent.getStringExtra("dns_name");
            final String mode = intent.getStringExtra("dns_mode");
            if (name == null || !name.matches("q29-[0-9]+\\.test") || (!"raw".equals(mode) && !"system".equals(mode) && !modeAllowed(mode))) return;
            final PendingResult pending = goAsync();
            Thread worker = new Thread(() -> {
                try { dnsProbe(context, name, mode); } finally { pending.finish(); }
            }, "q29-independent-dns");
            worker.setDaemon(true); worker.start(); return;
        }
        final String family = intent.hasExtra("family") ? intent.getStringExtra("family") : "ipv4";
        final String protocol = intent.hasExtra("protocol") ? intent.getStringExtra("protocol") : "udp";
        final int size = intent.getIntExtra("payload_bytes", tag.length());
        if ((!"ipv4".equals(family) && !"ipv6".equals(family)) || (!"tcp".equals(protocol) && !"udp".equals(protocol)) || (size != tag.length() && size != 257 && size != 16384)) return;
        final int run = intent.getIntExtra("burst_run", 0);
        final int count = intent.getIntExtra("burst_count", 0);
        final boolean observe = intent.getBooleanExtra("observe_network", false);
        if (run < 0 || (run != 0 && (count < 1 || count > (observe ? 24 : 12))) || (run == 0 && count != 0)) return;
        final PendingResult pending = goAsync();
        Thread worker = new Thread(() -> {
            ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
            ConnectivityManager.NetworkCallback observer = new ConnectivityManager.NetworkCallback() {
                private void event(String kind, Network network) {
                    record("BURST_NETWORK run=" + run + " uid=" + Process.myUid() + " event=" + kind + " network=" + network + " device_ms=" + System.currentTimeMillis());
                }
                @Override public void onAvailable(Network network) { event("AVAILABLE", network); }
                @Override public void onLost(Network network) { event("LOST", network); }
                @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities caps) { event("CAPABILITIES_vpn_" + caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN), network); }
                @Override public void onLinkPropertiesChanged(Network network, LinkProperties links) { event("LINKS_" + links.getInterfaceName(), network); }
            };
            boolean registered = false;
            try {
                if (observe) {
                    cm.registerDefaultNetworkCallback(observer);registered = true;
                    record("BURST_WATCH_READY run=" + run + " uid=" + Process.myUid() + " device_ms=" + System.currentTimeMillis());
                }
                if (run == 0) {
                    probe(tag, family, protocol, size, 0, 0, "COMPLETE tag=" + tag + " uid=" + Process.myUid() + " family=" + family + " protocol=" + protocol + " bytes=" + size);
                } else {
                    Thread[] children = new Thread[4];
                    int at = 0;
                    for (String f : new String[]{"ipv4", "ipv6"}) {
                        for (String proto : new String[]{"tcp", "udp"}) {
                            final String selectedFamily = f, selectedProtocol = proto;
                            children[at] = new Thread(() -> {
                                record("BURST_BEGIN run=" + run + " uid=" + Process.myUid() + " family=" + selectedFamily + " protocol=" + selectedProtocol + " count=" + count);
                                for (int sample = 0; sample < count; sample++) {
                                    if (observe) networkState(cm, run, sample, selectedFamily, selectedProtocol);
                                    String prefix = "BURST run=" + run + " sample=" + sample + " tag=" + tag + " uid=" + Process.myUid() + " family=" + selectedFamily + " protocol=" + selectedProtocol + " bytes=257 started_ms=" + System.currentTimeMillis();
                                    probe(tag, selectedFamily, selectedProtocol, 257, run, sample, prefix);
                                    try { Thread.sleep(150); }
                                    catch (InterruptedException error) { Thread.currentThread().interrupt(); return; }
                                }
                            }, "q29-burst-" + selectedFamily + "-" + selectedProtocol);
                            children[at].setDaemon(true);children[at++].start();
                        }
                    }
                    boolean interrupted = false;
                    for (Thread child : children) {
                        while (child.isAlive()) {
                            try { child.join(); }
                            catch (InterruptedException error) { interrupted = true; }
                        }
                    }
                    if (interrupted) Thread.currentThread().interrupt();
                    record("BURST_FINISHED run=" + run + " uid=" + Process.myUid());
                }
            } finally {
                if (registered) cm.unregisterNetworkCallback(observer);
                pending.finish();
            }
        }, "q29-independent-socket");
        worker.setDaemon(true); worker.start();
    }


    private static void networkState(ConnectivityManager cm, int run, int sample, String family, String protocol) {
        long before = System.currentTimeMillis();
        Network active = cm.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null : cm.getNetworkCapabilities(active);
        LinkProperties links = active == null ? null : cm.getLinkProperties(active);
        boolean v4 = false, v6 = false;
        if (links != null) for (LinkAddress address : links.getLinkAddresses()) {
            if (address.getAddress() instanceof java.net.Inet4Address) v4 = true;
            if (address.getAddress() instanceof java.net.Inet6Address) v6 = true;
        }
        record("BURST_STATE run=" + run + " sample=" + sample + " uid=" + Process.myUid() + " family=" + family + " protocol=" + protocol +
            " before_ms=" + before + " after_ms=" + System.currentTimeMillis() + " network=" + active + " vpn=" + (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) +
            " iface=" + (links == null ? "null" : links.getInterfaceName()) + " v4=" + v4 + " v6=" + v6);
    }

    private static boolean modeAllowed(String mode) {
        return "connectivity".equals(mode) || "auto".equals(mode) || "a".equals(mode) || "aaaa".equals(mode) || "auto-active".equals(mode) || "a-active".equals(mode) || "aaaa-active".equals(mode);
    }

    private static void dnsProbe(Context context, String name, String mode) {
        String prefix = "DNS uid=" + Process.myUid() + " mode=" + mode + " name=" + name + " started_ms=" + System.currentTimeMillis();
        try {
            if (modeAllowed(mode)) {
                ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
                Network active = cm.getActiveNetwork();
                record(prefix + " active=" + active + " capabilities=" + cm.getNetworkCapabilities(active) + " links=" + cm.getLinkProperties(active));
                if ("connectivity".equals(mode)) {
                    for (Network network : new Network[]{null, active}) {
                        for (String target : new String[]{"8.8.8.8", "2000::", "198.19.0.53", "2001:db8:29::1"}) {
                            String phase = "create";
                            FileDescriptor fd = null;
                            try {
                                InetAddress address = InetAddress.getByName(target);
                                fd = Os.socket(target.contains(":") ? OsConstants.AF_INET6 : OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);
                                phase = "bind";
                                if (network != null) network.bindSocket(fd);
                                phase = "connect";
                                Os.connect(fd, address, 0);
                                record(prefix + " network=" + network + " target=" + target + " phase=connected source=" + Os.getsockname(fd));
                            } catch (Exception error) { record(prefix + " network=" + network + " target=" + target + " phase=" + phase + " error=" + error); }
                            finally { if (fd != null) try { Os.close(fd); } catch (Exception error) { record(prefix + " close_error=" + error); } }
                        }
                    }
                    record(prefix + " done_ms=" + System.currentTimeMillis() + " diagnostic=COMPLETE");
                    return;
                }
                Network selected = mode.endsWith("-active") ? active : null;
                if (mode.endsWith("-active") && selected == null) throw new IllegalStateException("active network absent");
                CompletableFuture<List<InetAddress>> answer = new CompletableFuture<>();
                CancellationSignal cancel = new CancellationSignal();
                DnsResolver.Callback<List<InetAddress>> callback = new DnsResolver.Callback<List<InetAddress>>() {
                    public void onAnswer(List<InetAddress> values, int rcode) {
                        if (rcode == 0) answer.complete(values);
                        else answer.completeExceptionally(new IllegalStateException("DNS rcode=" + rcode));
                    }
                    public void onError(DnsResolver.DnsException error) { answer.completeExceptionally(error); }
                };
                try {
                    int flags = DnsResolver.FLAG_NO_CACHE_LOOKUP | DnsResolver.FLAG_NO_CACHE_STORE;
                    if (mode.startsWith("auto")) DnsResolver.getInstance().query(selected, name, flags, Runnable::run, cancel, callback);
                    else DnsResolver.getInstance().query(selected, name, mode.startsWith("aaaa") ? DnsResolver.TYPE_AAAA : DnsResolver.TYPE_A, flags, Runnable::run, cancel, callback);
                    List<InetAddress> values = answer.get(7, TimeUnit.SECONDS);
                    String[] addresses = new String[values.size()];
                    for (int i = 0; i < values.size(); i++) addresses[i] = values.get(i).getHostAddress();
                    Arrays.sort(addresses);
                    record(prefix + " done_ms=" + System.currentTimeMillis() + " answers=" + String.join(",", addresses));
                } finally { cancel.cancel(); }
            } else if ("system".equals(mode)) {
                CompletableFuture<InetAddress[]> answer = new CompletableFuture<>();
                Thread lookup = new Thread(() -> {
                    try { answer.complete(InetAddress.getAllByName(name)); }
                    catch (Exception error) { answer.completeExceptionally(error); }
                }, "q29-default-system-resolver");
                lookup.setDaemon(true); lookup.start();
                InetAddress[] values = answer.get(7, TimeUnit.SECONDS);
                String[] addresses = new String[values.length];
                for (int i = 0; i < values.length; i++) addresses[i] = values[i].getHostAddress();
                Arrays.sort(addresses);
                record(prefix + " done_ms=" + System.currentTimeMillis() + " answers=" + String.join(",", addresses));
            } else {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                DataOutputStream data = new DataOutputStream(bytes);
                data.writeShort(0x2929); data.writeShort(0x0100); data.writeShort(1);
                data.writeShort(0); data.writeShort(0); data.writeShort(0);
                for (String label : name.split("\\.")) { byte[] value = label.getBytes(StandardCharsets.US_ASCII); data.writeByte(value.length); data.write(value); }
                data.writeByte(0); data.writeShort(1); data.writeShort(1);
                byte[] question = bytes.toByteArray();
                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.setSoTimeout(1500); socket.connect(InetAddress.getByName("198.19.0.53"), 53);
                    socket.send(new DatagramPacket(question, question.length));
                    DatagramPacket packet = new DatagramPacket(new byte[4096], 4096); socket.receive(packet);
                    byte[] reply = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                    if (reply.length < question.length || reply[0] != 0x29 || reply[1] != 0x29 || (reply[2] & 0x80) == 0 || (reply[3] & 15) != 0 || reply[6] != 0 || reply[7] != 1 || !Arrays.equals(Arrays.copyOfRange(reply, 12, question.length), Arrays.copyOfRange(question, 12, question.length))) throw new IllegalStateException("DNS reply differs");
                    record(prefix + " done_ms=" + System.currentTimeMillis() + " source=" + socket.getLocalAddress().getHostAddress() + " reply_sha256=" + sha(reply));
                }
            }
        } catch (Exception error) {
            record(prefix + " done_ms=" + System.currentTimeMillis() + " error=" + error.getClass().getSimpleName() + ":" + error.getMessage());
        }
    }

    private static void probe(String tag, String family, String protocol, int size, int run, int sample, String prefix) {
            try {
                InetAddress host = InetAddress.getByName("ipv6".equals(family) ? "2001:db8:29::1" : "198.19.0.1");
                byte[] data = new byte[size];
                for (int i = 0; i < data.length; i++) data[i] = (byte) ((i * 31 + 17) % 251);
                byte[] marker = tag.getBytes(StandardCharsets.UTF_8);
                System.arraycopy(marker, 0, data, 0, marker.length);
                if (run != 0) {
                    for (int shift = 0; shift < 4; shift++) {
                        data[marker.length + shift] = (byte) (run >>> (24 - 8 * shift));
                        data[marker.length + 4 + shift] = (byte) (sample >>> (24 - 8 * shift));
                    }
                }
                byte[] expected, received;
                String source;
                if ("tcp".equals(protocol)) {
                    expected = data.clone();
                    for (int i = 0; i < data.length; i++) expected[i] = data[data.length - 1 - i];
                    try (Socket socket = new Socket()) {
                        socket.setSoTimeout(run == 0 ? 3000 : 250);
                        socket.connect(new InetSocketAddress(host, 26000), run == 0 ? 2000 : 250);
                        source = socket.getLocalAddress().getHostAddress();
                        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                        output.writeInt(data.length); output.write(data); output.flush();
                        DataInputStream input = new DataInputStream(socket.getInputStream());
                        if (input.readInt() != data.length) throw new IllegalStateException("TCP reply length differs");
                        received = new byte[data.length]; input.readFully(received);
                    }
                } else {
                    expected = new byte[data.length + 4];
                    System.arraycopy("Q29:".getBytes(StandardCharsets.UTF_8), 0, expected, 0, 4);
                    System.arraycopy(data, 0, expected, 4, data.length);
                    try (DatagramSocket socket = new DatagramSocket()) {
                        socket.setSoTimeout(run == 0 ? 1500 : 250); socket.connect(host, 26000);
                        source = socket.getLocalAddress().getHostAddress();
                        socket.send(new DatagramPacket(data, data.length));
                        DatagramPacket reply = new DatagramPacket(new byte[expected.length + 1], expected.length + 1);
                        socket.receive(reply);
                        received = Arrays.copyOfRange(reply.getData(), reply.getOffset(), reply.getOffset() + reply.getLength());
                    }
                }
                if (!Arrays.equals(expected, received)) throw new IllegalStateException("Payload bytes differ");
                record(prefix + (run == 0 ? "" : " done_ms=" + System.currentTimeMillis()) + " source=" + source + " reply=Q29:" + tag + " sha256=" + sha(data) + " reply_sha256=" + sha(received));
            } catch (Exception error) {
                record(prefix + (run == 0 ? "" : " done_ms=" + System.currentTimeMillis()) + " error=" + error.getClass().getSimpleName() + ":" + error.getMessage());

            }
    }
}
