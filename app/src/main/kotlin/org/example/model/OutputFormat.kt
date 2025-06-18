package org.example.model

sealed class OutputFormat(val value: String) {
    data object TXT : OutputFormat("TXT")
    data object JSON : OutputFormat("JSON")
    data object YAML : OutputFormat("YAML")
    data object UNKNOWN : OutputFormat("UNKNOWN")

    companion object {
        fun valueOf(value: String): OutputFormat {
            return when (value.uppercase()) {
                "TXT" -> TXT
                "JSON" -> JSON
                "YAML" -> YAML
                else -> UNKNOWN
            }
        }
    }
}
