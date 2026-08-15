using System.Globalization;

namespace Qeli.Shared.Model;

/// <summary>
/// Resolves an enabled/disabled pair used by the desktop profile-editor presets.
/// A value absent from the fixed presets is deliberately returned unchanged and
/// marked custom; silently choosing a nearby preset would rewrite a manual INI edit.
/// </summary>
public readonly record struct PairPresetSelection(string Tag, bool IsCustom)
{
    public static PairPresetSelection Resolve(
        bool enabled,
        long first,
        long second,
        IEnumerable<string?> availableTags)
    {
        var tag = enabled
            ? $"{first.ToString(CultureInfo.InvariantCulture)},{second.ToString(CultureInfo.InvariantCulture)}"
            : "off";
        var found = availableTags.Any(candidate =>
            string.Equals(candidate, tag, StringComparison.Ordinal));
        return new PairPresetSelection(tag, IsCustom: !found);
    }
}
