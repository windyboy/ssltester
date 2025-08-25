package org.example.validation

import org.example.SSLConstants
import org.example.exception.SSLTestException
import org.example.model.SSLTestConfig

/**
 * SSL测试配置验证器。
 * 负责验证配置参数的有效性和一致性。
 */
class ConfigurationValidator {
    /**
     * 验证SSL测试配置。
     * @param config 要验证的配置
     * @return 验证结果
     */
    fun validate(config: SSLTestConfig): ValidationResult {
        val errors = mutableListOf<ValidationError>()

        // 验证超时设置
        validateTimeouts(config, errors)

        // 验证重试设置
        validateRetrySettings(config, errors)

        // 验证输出文件路径
        validateOutputFile(config, errors)

        // 验证配置一致性
        validateConfigurationConsistency(config, errors)

        return if (errors.isEmpty()) {
            ValidationResult.Success
        } else {
            ValidationResult.Failure(errors)
        }
    }

    /**
     * 验证超时设置。
     */
    private fun validateTimeouts(
        config: SSLTestConfig,
        errors: MutableList<ValidationError>,
    ) {
        // 连接超时验证
        if (config.connectionTimeout < SSLConstants.MIN_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "connectionTimeout",
                    message = "Connection timeout must be at least ${SSLConstants.MIN_TIMEOUT}ms",
                    expectedValue = ">= ${SSLConstants.MIN_TIMEOUT}ms",
                    actualValue = "${config.connectionTimeout}ms",
                ),
            )
        }

        if (config.connectionTimeout > SSLConstants.MAX_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "connectionTimeout",
                    message = "Connection timeout cannot exceed ${SSLConstants.MAX_TIMEOUT}ms",
                    expectedValue = "<= ${SSLConstants.MAX_TIMEOUT}ms",
                    actualValue = "${config.connectionTimeout}ms",
                ),
            )
        }

        // 读取超时验证
        if (config.readTimeout < SSLConstants.MIN_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "readTimeout",
                    message = "Read timeout must be at least ${SSLConstants.MIN_TIMEOUT}ms",
                    expectedValue = ">= ${SSLConstants.MIN_TIMEOUT}ms",
                    actualValue = "${config.readTimeout}ms",
                ),
            )
        }

        if (config.readTimeout > SSLConstants.MAX_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "readTimeout",
                    message = "Read timeout cannot exceed ${SSLConstants.MAX_TIMEOUT}ms",
                    expectedValue = "<= ${SSLConstants.MAX_TIMEOUT}ms",
                    actualValue = "${config.readTimeout}ms",
                ),
            )
        }

        // 握手超时验证
        if (config.handshakeTimeout < SSLConstants.MIN_HANDSHAKE_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "handshakeTimeout",
                    message = "Handshake timeout must be at least ${SSLConstants.MIN_HANDSHAKE_TIMEOUT}ms",
                    expectedValue = ">= ${SSLConstants.MIN_HANDSHAKE_TIMEOUT}ms",
                    actualValue = "${config.handshakeTimeout}ms",
                ),
            )
        }

        if (config.handshakeTimeout > SSLConstants.MAX_HANDSHAKE_TIMEOUT) {
            errors.add(
                ValidationError(
                    field = "handshakeTimeout",
                    message = "Handshake timeout cannot exceed ${SSLConstants.MAX_HANDSHAKE_TIMEOUT}ms",
                    expectedValue = "<= ${SSLConstants.MAX_HANDSHAKE_TIMEOUT}ms",
                    actualValue = "${config.handshakeTimeout}ms",
                ),
            )
        }
    }

    /**
     * 验证重试设置。
     */
    private fun validateRetrySettings(
        config: SSLTestConfig,
        errors: MutableList<ValidationError>,
    ) {
        if (config.maxRetries < 0) {
            errors.add(
                ValidationError(
                    field = "maxRetries",
                    message = "Max retries cannot be negative",
                    expectedValue = ">= 0",
                    actualValue = config.maxRetries.toString(),
                ),
            )
        }

        if (config.maxRetries > SSLConstants.MAX_RETRIES) {
            errors.add(
                ValidationError(
                    field = "maxRetries",
                    message = "Max retries cannot exceed ${SSLConstants.MAX_RETRIES}",
                    expectedValue = "<= ${SSLConstants.MAX_RETRIES}",
                    actualValue = config.maxRetries.toString(),
                ),
            )
        }

        if (config.retryDelay < 0) {
            errors.add(
                ValidationError(
                    field = "retryDelay",
                    message = "Retry delay cannot be negative",
                    expectedValue = ">= 0ms",
                    actualValue = "${config.retryDelay}ms",
                ),
            )
        }

        if (config.retryDelay > SSLConstants.MAX_RETRY_DELAY) {
            errors.add(
                ValidationError(
                    field = "retryDelay",
                    message = "Retry delay cannot exceed ${SSLConstants.MAX_RETRY_DELAY}ms",
                    expectedValue = "<= ${SSLConstants.MAX_RETRY_DELAY}ms",
                    actualValue = "${config.retryDelay}ms",
                ),
            )
        }
    }

    /**
     * 验证输出文件路径。
     */
    private fun validateOutputFile(
        config: SSLTestConfig,
        errors: MutableList<ValidationError>,
    ) {
        config.outputFile?.let { filePath ->
            if (filePath.isBlank()) {
                errors.add(
                    ValidationError(
                        field = "outputFile",
                        message = "Output file path cannot be blank",
                        expectedValue = "Non-blank file path",
                        actualValue = "Blank string",
                    ),
                )
            }

            if (filePath.contains("..")) {
                errors.add(
                    ValidationError(
                        field = "outputFile",
                        message = "Output file path contains invalid characters",
                        expectedValue = "Valid file path without '..'",
                        actualValue = filePath,
                    ),
                )
            }

            // 检查文件扩展名是否与格式匹配
            val expectedExtension = config.format.getFileExtension()
            if (!filePath.endsWith(".$expectedExtension", ignoreCase = true)) {
                errors.add(
                    ValidationError(
                        field = "outputFile",
                        message = "Output file extension should match the selected format",
                        expectedValue = "File with .$expectedExtension extension",
                        actualValue = "File: $filePath",
                    ),
                )
            }
        }
    }

    /**
     * 验证配置一致性。
     */
    private fun validateConfigurationConsistency(
        config: SSLTestConfig,
        errors: MutableList<ValidationError>,
    ) {
        // 握手超时应该大于等于连接超时
        if (config.handshakeTimeout < config.connectionTimeout) {
            errors.add(
                ValidationError(
                    field = "handshakeTimeout",
                    message = "Handshake timeout should be greater than or equal to connection timeout",
                    expectedValue = ">= ${config.connectionTimeout}ms",
                    actualValue = "${config.handshakeTimeout}ms",
                ),
            )
        }

        // 读取超时应该大于等于连接超时
        if (config.readTimeout < config.connectionTimeout) {
            errors.add(
                ValidationError(
                    field = "readTimeout",
                    message = "Read timeout should be greater than or equal to connection timeout",
                    expectedValue = ">= ${config.connectionTimeout}ms",
                    actualValue = "${config.readTimeout}ms",
                ),
            )
        }
    }

    /**
     * 验证结果。
     */
    sealed class ValidationResult {
        object Success : ValidationResult()

        data class Failure(val errors: List<ValidationError>) : ValidationResult()
    }

    /**
     * 验证错误。
     */
    data class ValidationError(
        val field: String,
        val message: String,
        val expectedValue: String,
        val actualValue: String,
    ) {
        fun toException(): SSLTestException.ConfigurationError {
            return SSLTestException.ConfigurationError(
                message = "$field: $message",
                configField = field,
                expectedValue = expectedValue,
                actualValue = actualValue,
            )
        }
    }

    companion object {
        /**
         * 快速验证配置。
         * @throws SSLTestException.ConfigurationError 当配置无效时
         */
        fun validateOrThrow(config: SSLTestConfig) {
            val validator = ConfigurationValidator()
            val result = validator.validate(config)

            if (result is ValidationResult.Failure) {
                val errorMessages =
                    result.errors.joinToString("; ") {
                        "${it.field}: ${it.message}"
                    }
                throw SSLTestException.ConfigurationError(
                    message = "Invalid SSL test configuration: $errorMessages",
                    configField = "MULTIPLE",
                    expectedValue = "Valid configuration values",
                    actualValue = "Invalid values provided",
                )
            }
        }
    }
}
