package org.example.config

import java.io.File
import org.example.exception.SSLTestException

/**
 * Configuration for SSL testing.
 */
data class SSLTestConfig(
    val url: String,
    val connectTimeout: Int = 5000,
    val readTimeout: Int = 5000,
    val outputFormat: OutputFormat = OutputFormat.TEXT,
    val outputFile: String? = null,
    val trustStore: String? = null,
    val trustStorePassword: String? = null,
    val clientCertFile: String? = null,
    val clientKeyFile: String? = null,
    val clientKeyPassword: String? = null,
    val verifyHostname: Boolean = true,
    val failOnError: Boolean = false
) {
    /**
     * Supported output formats.
     */
    enum class OutputFormat {
        TEXT,
        JSON,
        YAML
    }

    /**
     * Validates the configuration.
     * @throws SSLTestException if the configuration is invalid
     */
    fun validate() {
        if (url.isBlank()) {
            throw SSLTestException("URL cannot be empty")
        }

        if (connectTimeout <= 0) {
            throw SSLTestException("Connect timeout must be positive")
        }

        if (readTimeout <= 0) {
            throw SSLTestException("Read timeout must be positive")
        }

        if (trustStore != null && !File(trustStore).exists()) {
            throw SSLTestException("Trust store file does not exist: $trustStore")
        }

        if (clientCertFile != null && !File(clientCertFile).exists()) {
            throw SSLTestException("Client certificate file does not exist: $clientCertFile")
        }

        if (clientKeyFile != null && !File(clientKeyFile).exists()) {
            throw SSLTestException("Client key file does not exist: $clientKeyFile")
        }
    }

    companion object {
        /**
         * Parses command line arguments into a configuration.
         * @param args The command line arguments
         * @return The parsed configuration
         * @throws SSLTestException if the arguments are invalid
         */
        fun parseArgs(args: Array<String>): SSLTestConfig {
            if (args.isEmpty()) {
                throw SSLTestException("URL is required")
            }

            val url = args[0]
            var connectTimeout = 5000
            var readTimeout = 5000
            var outputFormat = OutputFormat.TEXT
            var outputFile: String? = null
            var trustStore: String? = null
            var trustStorePassword: String? = null
            var clientCertFile: String? = null
            var clientKeyFile: String? = null
            var clientKeyPassword: String? = null
            var verifyHostname = true
            var failOnError = false

            var i = 1
            while (i < args.size) {
                when (args[i]) {
                    "--connect-timeout" -> connectTimeout = args[++i].toInt()
                    "--read-timeout" -> readTimeout = args[++i].toInt()
                    "--output-format" -> outputFormat = OutputFormat.valueOf(args[++i].uppercase())
                    "--output-file" -> outputFile = args[++i]
                    "--trust-store" -> trustStore = args[++i]
                    "--trust-store-password" -> trustStorePassword = args[++i]
                    "--client-cert" -> clientCertFile = args[++i]
                    "--client-key" -> clientKeyFile = args[++i]
                    "--client-key-password" -> clientKeyPassword = args[++i]
                    "--no-verify-hostname" -> verifyHostname = false
                    "--fail-on-error" -> failOnError = true
                    else -> throw SSLTestException("Unknown argument: ${args[i]}")
                }
                i++
            }

            return SSLTestConfig(
                url = url,
                connectTimeout = connectTimeout,
                readTimeout = readTimeout,
                outputFormat = outputFormat,
                outputFile = outputFile,
                trustStore = trustStore,
                trustStorePassword = trustStorePassword,
                clientCertFile = clientCertFile,
                clientKeyFile = clientKeyFile,
                clientKeyPassword = clientKeyPassword,
                verifyHostname = verifyHostname,
                failOnError = failOnError
            ).apply { validate() }
        }
    }
} 