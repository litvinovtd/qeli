package com.qeli

/**
 * Changes only the per-app keys in the [qeli] section. The shared parser validates
 * the resulting INI; this narrow text edit keeps comments and unrelated sections.
 */
internal object ProfileAppsEditor {
    fun replace(ini: String, mode: String, packages: List<String>): String {
        require(mode in setOf("all", "include", "exclude")) { "invalid per-app mode" }
        val active = mode != "all" && packages.isNotEmpty()
        var inQeli = false
        var foundQeli = false
        return buildString {
            fun appendSelection() {
                if (active) {
                    append("apps_mode = ").append(mode).append('\n')
                    append("apps = ").append(packages.joinToString(", ")).append('\n')
                }
            }
            for (raw in ini.trimEnd('\r', '\n').lineSequence()) {
                val line = raw.removeSuffix("\r")
                val trimmed = line.trim()
                val header = trimmed.startsWith("[") && trimmed.endsWith("]")
                if (header) {
                    if (inQeli) appendSelection()
                    inQeli = trimmed.equals("[qeli]", ignoreCase = true)
                    foundQeli = foundQeli || inQeli
                }
                val key = if (inQeli && !header && !trimmed.startsWith("#")
                    && !trimmed.startsWith(";") && '=' in trimmed
                ) trimmed.substringBefore('=').trim() else ""
                if (inQeli && (key.equals("apps_mode", ignoreCase = true)
                        || key.equals("apps", ignoreCase = true))) continue
                append(line).append('\n')
            }
            if (inQeli) appendSelection()
            require(foundQeli) { "missing [qeli] section" }
        }
    }
}
