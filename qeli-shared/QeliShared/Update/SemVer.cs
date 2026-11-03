namespace Qeli.Shared;
/// <summary>Shared native numeric release-version policy.</summary>
public static class SemVer {
    public static string Normalize(string? s) => Model.ConfigCore.Policy("version_normalize",new { value=s ?? "" }).GetProperty("value").GetString()!;
    public static int Compare(string? a,string? b) => Model.ConfigCore.Policy("version_compare",new { a=a ?? "", b=b ?? "" }).GetProperty("value").GetInt32();
    public static bool IsNewer(string? latest,string? current) => Compare(latest,current)>0;
}
