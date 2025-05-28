package org.example

import org.example.cert.CertificateValidator
import org.example.cert.ClientCertificateManager
import org.example.config.SSLTestConfig
import org.example.config.SSLTestConfigFile
import org.example.exception.SSLTestException
import org.example.output.ResultFormatter
import org.slf4j.LoggerFactory
import picocli.CommandLine
import picocli.CommandLine.Command
import javax.net.ssl.HttpsURLConnection
import java.io.IOException
import java.net.URI
import java.net.URL
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.Callable

/**
 * A command-line tool (using Picocli) for testing SSL/TLS connections to a given HTTPS URL.
 * Key functionalities include:
 * <ul>
 *   <li>Establishing an HTTPS connection to the specified URL.</li>
 *   <li>Validating the server's certificate chain against a truststore (system default or custom).</li>
 *   <li>Performing hostname verification (matching hostname against SANs/CN in the certificate).</li>
 *   <li>Requesting OCSP stapling by setting relevant system/security properties.</li>
 *   <li>Assessing and reporting the strength of the negotiated TLS protocol and cipher suite.</li>
 *   <li>Extracting and displaying detailed information about the server's certificates.</li>
 *   <li>Providing results in various formats (TEXT, JSON, YAML).</li>
 * </ul>
 */
@Command(
    name = "ssltest",
    description = ["SSL/TLS Test Tool - Validates HTTPS connections, checks certificate chains, and assesses security configurations."],
    mixinStandardHelpOptions = true
)
class SSLTest : Callable<Int> {
    companion object {
        private val logger = LoggerFactory.getLogger(SSLTest::class.java)

        // Exit codes
        const val EXIT_SUCCESS = 0
        const val EXIT_INVALID_ARGS = 1
        const val EXIT_SSL_HANDSHAKE_ERROR = 2
        const val EXIT_CONNECTION_ERROR = 3
        const val EXIT_HOSTNAME_VERIFICATION_ERROR = 5
        const val EXIT_UNEXPECTED_ERROR = 99

        @JvmStatic
        fun main(args: Array<String>) {
            val commandLine = CommandLine(SSLTest())
            val exitCode = commandLine.execute(*args)
            System.exit(exitCode)
        }
    }

    /**
     * Configuration object populated by Picocli with command-line arguments.
     */
    @CommandLine.Mixin
    private val config: SSLTestConfig
    private val certValidator: CertificateValidator
    private val resultFormatter: ResultFormatter
    private val clientCertManager: ClientCertificateManager
    private val result = mutableMapOf<String, Any>()

    // No-arg constructor for CLI use
    constructor() : this(SSLTestConfig())

    // Constructor for test/dependency injection
    constructor(config: SSLTestConfig) {
        this.config = config
        this.certValidator = CertificateValidator(config)
        this.resultFormatter = ResultFormatter(config)
        this.clientCertManager = ClientCertificateManager(config)
    }

    /**
     * Main execution method called by Picocli when the command is run.
     * It orchestrates the SSL/TLS test by:
     * <ol>
     *   <li>Setting up system/security properties to enable OCSP stapling requests.</li>
     *   <li>Parsing and validating the target URL.</li>
     *   <li>Executing the main test logic via {@link #testSSLConnection(URL)}.</li>
     *   <li>Formatting and outputting the collected results.</li>
     *   <li>Handling any {@link SSLTestException} or other exceptions that occur.</li>
     *   <li>Restoring original system/security properties in a finally block.</li>
     * </ol>
     *
     * @return The exit code for the application.
     */
    override fun call(): Int {
        var originalEnableStatusRequestExtension: String? = null
        var originalOcspEnable: String? = null
        try {
            // Store original values and set new values for OCSP stapling
            originalEnableStatusRequestExtension = System.getProperty("jdk.tls.client.enableStatusRequestExtension")
            originalOcspEnable = java.security.Security.getProperty("ocsp.enable")

            System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true")
            java.security.Security.setProperty("ocsp.enable", "true")
            logger.debug("Set jdk.tls.client.enableStatusRequestExtension=true, ocsp.enable=true")

            if (config.url.isBlank()) {
                throw SSLTestException("URL is required", EXIT_INVALID_ARGS)
            }

            // Load configuration from file if specified
            config.configFile?.let { configFile ->
                try {
                    val fileConfig = SSLTestConfigFile.loadConfig(configFile)
                    SSLTestConfigFile.applyConfig(fileConfig, config)
                } catch (e: IOException) {
                    throw SSLTestException("Failed to load configuration file: ${e.message}", EXIT_INVALID_ARGS, e)
                }
            }

            val parsedUrl = parseAndValidateUrl(config.url)
            testSSLConnection(parsedUrl)
            resultFormatter.formatAndOutput(result)
            return EXIT_SUCCESS
        } catch (e: SSLTestException) {
            handleError(e.message ?: "Unknown error", e.cause, e.exitCode)
            return e.exitCode
        } catch (e: Exception) {
            handleError("Unexpected error: ${e.message}", e, EXIT_UNEXPECTED_ERROR)
            return EXIT_UNEXPECTED_ERROR
        } finally {
            // Restore original property values
            logger.debug("Restoring original OCSP properties...")
            originalEnableStatusRequestExtension?.let {
                System.setProperty("jdk.tls.client.enableStatusRequestExtension", it)
            } ?: System.clearProperty("jdk.tls.client.enableStatusRequestExtension")

            originalOcspEnable?.let {
                java.security.Security.setProperty("ocsp.enable", it)
            } ?: run {
                java.security.Security.setProperty("ocsp.enable", "false")
            }
            logger.debug("Restored OCSP properties to their original values.")
        }
    }

    /**
     * Handles errors by logging them and preparing error information for output.
     * It populates the {@code result} map with error details which are then formatted
     * and displayed by the {@link ResultFormatter}.
     */
    private fun handleError(message: String, cause: Throwable?, exitCode: Int) {
        resultFormatter.logError(message, cause, exitCode)
        result["error"] = message
        cause?.let { result["errorCause"] = it.message ?: "" }
        result["exitCode"] = exitCode.toString()
        resultFormatter.formatAndOutput(result)
    }

    /**
     * Parses the input URL string and validates that it uses the HTTPS protocol.
     *
     * @param urlStr The URL string to parse and validate.
     * @return A {@link URL} object if the URL is valid and uses HTTPS.
     * @throws SSLTestException If the URL is malformed or does not use the HTTPS protocol.
     */
    private fun parseAndValidateUrl(urlStr: String): URL {
        return try {
            val url = URI(urlStr).toURL()
            if (!url.protocol.equals("https", ignoreCase = true)) {
                throw SSLTestException("URL must use HTTPS protocol", EXIT_INVALID_ARGS)
            }
            url
        } catch (e: Exception) {
            throw SSLTestException("Invalid URL: ${e.message}", EXIT_INVALID_ARGS, e)
        }
    }

    /**
     * Orchestrates the SSL/TLS connection test to the specified URL.
     */
    private fun testSSLConnection(url: URL) {
        var conn: HttpsURLConnection? = null
        try {
            conn = setupConnection(url)
            val responseCode = conn.responseCode
            val cipherSuite = conn.cipherSuite

            logger.info("→ HTTP Status  : {}", responseCode)
            logger.info("→ Cipher Suite : {}", cipherSuite)

            result["httpStatus"] = responseCode
            result["cipherSuite"] = cipherSuite

            // Get and validate certificates
            val certs = conn.serverCertificates
            if (certs.isNullOrEmpty()) {
                throw SSLTestException("No certificates received from server", EXIT_SSL_HANDSHAKE_ERROR)
            }

            // First verify the hostname
            val serverCert = certs[0] as X509Certificate
            if (!certValidator.verifyHostname(serverCert, url.host ?: "")) {
                throw SSLTestException("Hostname verification failed", EXIT_HOSTNAME_VERIFICATION_ERROR)
            }

            // Then validate the certificate chain
            certValidator.validateCertificateChain(certs, url.host ?: "")
            processCertificates(certs.map { it as X509Certificate }.toTypedArray())

        } finally {
            conn?.disconnect()
        }
    }

    private fun setupConnection(url: URL): HttpsURLConnection {
        val conn = url.openConnection() as HttpsURLConnection
        conn.connectTimeout = config.connectionTimeout
        conn.readTimeout = config.readTimeout
        conn.instanceFollowRedirects = config.followRedirects
        return conn
    }

    private fun processCertificates(certs: Array<X509Certificate>) {
        val certInfoList = certs.map { cert ->
            mapOf(
                "subject" to cert.subjectX500Principal.name,
                "issuer" to cert.issuerX500Principal.name,
                "validFrom" to cert.notBefore,
                "validTo" to cert.notAfter,
                "serialNumber" to cert.serialNumber.toString(16),
                "signatureAlgorithm" to cert.sigAlgName
            )
        }
        result["certificates"] = certInfoList
    }
}
