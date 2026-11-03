package com.qeli;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

// A private app_process harness: no APK installation, VpnService or persisted app state.
class TransportCore {
    static native int nativeAbiVersion();
    static native long nativeCoreCapabilities();
    static native long nativeNew(byte[] config, long capabilities, int capacity);
    static native int nativeStart(long handle);
    static native int nativeStop(long handle);
    static native int nativeState(long handle);
    static native int nativeSetDeviceId(long handle, byte[] identity);
    static native byte[] nativePollEvent(long handle);
    static native long[] nativeStats(long handle);
    static native long nativePublishHandshakeNetwork(long handle, byte[] input);
    static native int nativeNetworkPlanResult(long handle, long generation, int code, byte[] reason);
    static native int nativeFree(long handle);
    static native int nativeRunTransport(long handle, byte[] input);
    static native void nativeCancelUdpReachability(long id);
    static native long nativeUdpReachabilityCancellable(byte[] config, byte[] host, int timeout, long id);
    static int checks;
    static void check(String label, boolean value) {
        if (!value) throw new AssertionError(label);
        ++checks; System.out.println("PASS "+label);
    }
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    static byte[] config(String protocol) {
        return bytes("[qeli]\nserver = 127.0.0.1:443\nproto = "+protocol+"\nuser = test\npass = fixture-only\nkey = "+"11".repeat(32)+"\nmode = fake-tls\ngateway = false\n");
    }
    static List<byte[]> drain(long handle) {
        List<byte[]> events = new ArrayList<>();
        for (int i=0; i<256; ++i) {
            byte[] event = nativePollEvent(handle);
            if (event == null) return events;
            ByteBuffer frame = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN);
            if (event.length < 48 || frame.getInt(0) != 48 || frame.getInt(44) != event.length-48)
                throw new AssertionError("malformed JNI event frame");
            events.add(event);
        }
        throw new AssertionError("JNI event queue did not quiesce");
    }
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        check("ABI version", nativeAbiVersion()==0x10010);
        check("native data plane capability", (nativeCoreCapabilities() & (1L<<8)) != 0);
        check("invalid config and negative event capacity refused", nativeNew(bytes("{}"),7,0)==0 && nativeNew(config("tcp"),7,-1)==0);
        long handle = nativeNew(config("tcp"),7,0); check("Created handle",handle!=0 && nativeState(handle)==0);
        try {
            byte[] identity = new byte[16];
            check("zero device identity refused",nativeSetDeviceId(handle,identity)==-1); identity[0]=1;
            check("valid device identity copied",nativeSetDeviceId(handle,identity)==0);
            check("start transition",nativeStart(handle)==0 && nativeStart(handle)==-3);
            JSONObject auth = new JSONObject().put("client_ip","10.8.0.2").put("server_ip","10.8.0.1").put("prefix",24).put("mtu",1400).put("dns","10.8.0.1").put("dns_port",53).put("routes",new org.json.JSONArray());
            byte[] input = bytes(new JSONObject().put("auth_ok","OK:"+auth.toString()).put("effective_mtu",1400).toString());
            long generation = nativePublishHandshakeNetwork(handle,input);
            check("NetworkPlan pauses generation",generation==1 && nativeState(handle)==2);
            int plans=0;
            for (byte[] event:drain(handle)) {
                ByteBuffer header=ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN);
                if(header.getInt(8)==2) {
                    JSONObject plan=new JSONObject(new String(event,48,event.length-48,StandardCharsets.UTF_8));
                    check("JNI plan framing and owned values",header.getLong(32)==generation && plan.getString("tunnel_address").equals("10.8.0.2")); ++plans;
                }
            }
            check("one plan emitted",plans==1);
            check("stale generation rejected",nativeNetworkPlanResult(handle,generation+1,0,new byte[0])==-4 && nativeState(handle)==2);
            check("ACK starts control state",nativeNetworkPlanResult(handle,generation,0,new byte[0])==0 && nativeState(handle)==3);
            check("stats frame",nativeStats(handle).length==8);
            check("stop cancels generation",nativeStop(handle)==0 && nativeState(handle)==5);
            check("stop is idempotent",nativeStop(handle)==0);
        } finally { check("free handle",nativeFree(handle)==0); }
        check("double free and stale state",nativeFree(handle)==-7 && nativeState(handle)==-7);
        boolean invalidThrown=false;
        try { nativePollEvent(handle); } catch(IllegalStateException expected) { invalidThrown=true; }
        check("invalid poll throws instead of returning empty queue",invalidThrown);
        long prior=handle;
        for(int i=0;i<100;++i) {
            long current=nativeNew(config("tcp"),7,0);
            if(current==0 || current==prior || nativeFree(current)!=0 || nativeState(prior)!=-7)
                throw new AssertionError("registry generation reused");
            prior=current;
        }
        check("100 JNI handle reuse cycles",true);
        long probeId=0x71656c69L; nativeCancelUdpReachability(probeId); long start=System.nanoTime();
        check("UDP cancellation before registration",nativeUdpReachabilityCancellable(config("udp"),bytes("127.0.0.1"),1000,probeId)<0 && System.nanoTime()-start<1_000_000_000L);
        // VpnService.protect is deliberately never ACKed: cancel/free must end the real runner.
        long active=nativeNew(config("tcp"),7|(1L<<5),0);
        byte[] identity=new byte[16];identity[0]=1;
        if(nativeSetDeviceId(active,identity)!=0 || nativeStart(active)!=0) throw new AssertionError("runner setup");
        int[] outcome={Integer.MIN_VALUE};
        final long running=active;
        Thread runner=new Thread(()->outcome[0]=nativeRunTransport(running,bytes("{\"carrier_addresses\":[\"127.0.0.1\"]}")));
        runner.start(); boolean protectSeen=false;
        long deadline=System.nanoTime()+10_000_000_000L;
        try {
            while(System.nanoTime()<deadline && !protectSeen) {
                for(byte[] event:drain(active)) if(ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN).getInt(8)==4) protectSeen=true;
                if(!protectSeen) Thread.sleep(10);
            }
            check("real runner pauses at socket-protect callback",protectSeen);
            check("free cancels leased JNI runner",nativeFree(active)==0); active=0;
            runner.join(3000);
            check("JNI runner joins before protect ACK",!runner.isAlive() && outcome[0]==0);
        } finally {
            if(active!=0) nativeFree(active);
            runner.join(3000);
        }
        System.out.println("Q22_JNI_PASS checks="+checks);
    }
}
