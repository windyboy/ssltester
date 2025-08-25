package org.example.model

import org.example.SSLConstants
import org.example.validation.ConfigurationValidator

/**
 * SSL 测试配置。
 * 包含连接超时、输出格式、输出文件等配置项。
 */
data class SSLTestConfig(
    val connectionTimeout: Int = SSLConstants.DEFAULT_TIMEOUT,
    val readTimeout: Int = SSLConstants.DEFAULT_TIMEOUT,
    val handshakeTimeout: Int = SSLConstants.DEFAULT_HANDSHAKE_TIMEOUT,
    val format: OutputFormat = OutputFormat.TXT,
    val outputFile: String? = null,
    val enableHostnameVerification: Boolean = true,
    val enableOCSPValidation: Boolean = true,
    val maxRetries: Int = 1,
    val retryDelay: Long = 1000L,
) {
    /**
     * 验证配置参数的有效性。
     * @throws SSLTestException.ConfigurationError 当配置无效时
     */
    fun validate() {
        ConfigurationValidator.validateOrThrow(this)
    }

    companion object {
        /**
         * 创建默认配置。
         */
        fun default(): SSLTestConfig = SSLTestConfig()

        /**
         * 创建快速测试配置（较短超时）。
         */
        fun quickTest(): SSLTestConfig =
            SSLTestConfig(
                connectionTimeout = 2000,
                readTimeout = 2000,
                handshakeTimeout = 3000,
                maxRetries = 0,
            )

        /**
         * 创建详细测试配置（较长超时，启用所有验证）。
         */
        fun detailedTest(): SSLTestConfig =
            SSLTestConfig(
                connectionTimeout = 10000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 2,
                retryDelay = 2000L,
            )
    }
}
