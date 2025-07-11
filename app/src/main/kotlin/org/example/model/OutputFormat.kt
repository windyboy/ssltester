package org.example.model

/**
 * 输出格式类型枚举。
 * 支持 TXT、JSON、YAML、EMOJI 四种格式。
 */
sealed class OutputFormat(val value: String) {
    /** 文本格式 */
    data object TXT : OutputFormat("TXT")

    /** JSON 格式 */
    data object JSON : OutputFormat("JSON")

    /** YAML 格式 */
    data object YAML : OutputFormat("YAML")

    /** Emoji文本格式 */
    data object EMOJI : OutputFormat("EMOJI")

    /** 未知格式 */
    data object UNKNOWN : OutputFormat("UNKNOWN")

    companion object {
        /**
         * 根据字符串获取对应的输出格式。
         * @param value 格式字符串
         * @return 对应的 OutputFormat
         */
        fun valueOf(value: String): OutputFormat {
            return when (value.uppercase()) {
                "TXT" -> TXT
                "JSON" -> JSON
                "YAML" -> YAML
                "EMOJI" -> EMOJI
                else -> UNKNOWN
            }
        }
    }
}
