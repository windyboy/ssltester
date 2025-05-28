package org.example.output

import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import org.slf4j.LoggerFactory
import java.io.File
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule

/**
 * Handles the formatting of SSL/TLS test results into various output formats
 * (TEXT, JSON, YAML) and directs the output to the configured destination,
 * which can be a file or the standard console.
 */
class ResultFormatter(private val config: SSLTestConfig) {
    private val logger = LoggerFactory.getLogger(ResultFormatter::class.java)
    private val jsonMapper = ObjectMapper().registerKotlinModule()
    private val yamlMapper = ObjectMapper(YAMLFactory()).registerKotlinModule()

    /**
     * Formats the provided result map into the configured output format (TEXT, JSON, or YAML)
     * and writes it to the specified output file or to the console if no file is set.
     * Returns the formatted output string for testability.
     */
    fun formatAndOutput(result: Map<String, Any>): String {
        val formattedOutput = when (config.format) {
            SSLTestConfig.OutputFormat.TEXT -> formatAsText(result)
            SSLTestConfig.OutputFormat.JSON -> formatAsJson(result)
            SSLTestConfig.OutputFormat.YAML -> formatAsYaml(result)
        }

        if (config.outputFile != null) {
            config.outputFile?.writeText(formattedOutput)
        } else {
            println(formattedOutput)
        }
        return formattedOutput
    }

    /**
     * Logs an error message and its cause to the logger.
     *
     * @param message The error message
     * @param cause The cause of the error
     * @param exitCode The exit code associated with the error
     */
    fun logError(message: String, cause: Throwable?, exitCode: Int) {
        logger.error("Error: $message (Exit code: $exitCode)")
        cause?.let { logger.error("Cause: ${it.message}") }
    }

    private fun formatAsText(result: Map<String, Any>): String {
        val sb = StringBuilder()
        sb.appendLine("SSL Test Results")
        sb.appendLine("===============")

        result.forEach { (key, value) ->
            when (value) {
                is List<*> -> {
                    value.forEach { item ->
                        if (item is Map<*, *>) {
                            val map = item as Map<String, Any>
                            map.forEach { (k, v) ->
                                sb.appendLine("${formatKey(k)}: $v")
                            }
                        } else {
                            sb.appendLine("${formatKey(key)}: $item")
                        }
                    }
                }
                is Map<*, *> -> {
                    val map = value as Map<String, Any>
                    map.forEach { (k, v) ->
                        sb.appendLine("${formatKey(k)}: $v")
                    }
                }
                else -> {
                    sb.appendLine("${formatKey(key)}: $value")
                }
            }
        }

        return sb.toString()
    }

    private fun formatKey(key: String): String {
        return when (key) {
            "status" -> "Status"
            "httpStatus" -> "HTTP Status"
            "cipherSuite" -> "Cipher Suite"
            "hostnameVerified" -> "Hostname Verified"
            "error" -> "Error"
            "errorCause" -> "Cause"
            "subjectDN" -> "Subject"
            "issuerDN" -> "Issuer"
            "validFrom" -> "Valid From"
            "validUntil" -> "Valid Until"
            "signatureAlgorithm" -> "Signature Algorithm"
            else -> key.replaceFirstChar { it.uppercase() }
        }
    }

    private fun formatAsJson(result: Map<String, Any>): String {
        return jsonMapper.writeValueAsString(result)
    }

    private fun formatAsYaml(result: Map<String, Any>): String {
        return yamlMapper.writeValueAsString(result)
    }
} 