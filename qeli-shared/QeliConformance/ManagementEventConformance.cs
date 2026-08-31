using Qeli.Shared.Vpn;

namespace Qeli.Shared.Protocol;

internal static class ManagementEventConformance
{
    internal static void Run(Action<string, bool> check)
    {
        var kick = new NativeTransportCore.NativeEvent(
            NativeTransportCore.EventKick,
            NativeTransportCore.StateRunning,
            NativeTransportCore.PayloadJson,
            73,
            0,
            0,
            "{\"type\":\"kick\",\"reason\":\"administrative\",\"message\":\"Session stopped\",\"reconnect_allowed\":false}");
        var decodedKick = NativeTransportCore.DecodeManagement(kick,
            NativeTransportCore.EventKick);
        check("management-event: typed terminal KICK is decoded",
            decodedKick.Message == "Session stopped" && !decodedKick.ReconnectAllowed);

        var notice = kick with
        {
            Kind = NativeTransportCore.EventNotice,
            Payload = "{\"type\":\"notice\",\"kind\":\"quota_warning\",\"severity\":\"warning\",\"message\":\"Quota is 80% used\",\"value\":80}",
        };
        var decodedNotice = NativeTransportCore.DecodeManagement(notice,
            NativeTransportCore.EventNotice);
        check("management-event: typed NOTICE is decoded",
            decodedNotice.Message == "Quota is 80% used" && decodedNotice.ReconnectAllowed);

        bool mismatchRejected;
        try
        {
            NativeTransportCore.DecodeManagement(kick with
            {
                Payload = kick.Payload.Replace("\"kick\"", "\"notice\"",
                    StringComparison.Ordinal),
            }, NativeTransportCore.EventKick);
            mismatchRejected = false;
        }
        catch (InvalidDataException) { mismatchRejected = true; }
        check("management-event: ABI kind/type mismatch is rejected", mismatchRejected);

        bool malformedRejected;
        try
        {
            NativeTransportCore.DecodeManagement(kick with
            {
                Payload = "{\"type\":\"kick\",\"message\":\"line\\nfeed\",\"reconnect_allowed\":false}",
            }, NativeTransportCore.EventKick);
            malformedRejected = false;
        }
        catch (InvalidDataException) { malformedRejected = true; }
        check("management-event: control text is rejected", malformedRejected);

        bool policyRejected;
        try
        {
            NativeTransportCore.DecodeManagement(kick with
            {
                Payload = "{\"type\":\"kick\",\"message\":\"Session stopped\"}",
            }, NativeTransportCore.EventKick);
            policyRejected = false;
        }
        catch (InvalidDataException) { policyRejected = true; }
        check("management-event: KICK without reconnect policy is rejected", policyRejected);
    }
}
