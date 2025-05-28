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
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.HostnameVerifier
import java.security.KeyStore

/**
 * A command-line tool (using Picocli) for testing SSL/TLS connections to a given HTTPS URL.
 * Key functionalities include:
 * <ul>
 *   <li>Establishing an HTTPS connection to the specified URL.</li>
 *   <li>Validating the server's certificate chain against a truststore (system default or custom).</li>
 *   <li>Performing hostname verification (matching hostname against SANs/CN in the certificate).</li>
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
        const val EXIT_ERROR = 1
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
     *   <li>Parsing and validating the target URL.</li>
     *   <li>Executing the main test logic via {@link #testSSLConnection(URL)}.</li>
     *   <li>Formatting and outputting the collected results.</li>
     *   <li>Handling any {@link SSLTestException} or other exceptions that occur.</li>
     * </ol>
     *
     * @return The exit code for the application.
     */
    override fun call(): Int {
        try {
            if (config.url.isBlank()) {
                throw SSLTestException("URL is required", EXIT_INVALID_ARGS)
            }

            // Load configuration from file if specified
            config.configFile?.let { configFile ->
                try {
                    val fileConfig = SSLTestConfigFile.loadConfig(configFile.absolutePath)
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
            
            // Connect first before accessing properties
            conn.connect()
            
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
        
        // Set timeouts
        conn.connectTimeout = config.connectionTimeout
        conn.readTimeout = config.readTimeout
        
        // Set redirect following
        conn.instanceFollowRedirects = config.followRedirects
        
        // Configure SSL/TLS
        val sslContext = SSLContext.getInstance("TLS")
        val trustManagers = if (config.keystoreFile != null && config.keystorePassword != null) {
            // Use custom keystore
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
            trustStore.load(config.keystoreFile?.inputStream(), config.keystorePassword?.toCharArray())
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(trustStore)
            trustManagerFactory.trustManagers
        } else {
            // Use default truststore
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            trustManagerFactory.trustManagers
        }
        
        // Initialize SSL context with trust managers
        sslContext.init(null, trustManagers, null)
        
        // Set SSL socket factory
        conn.sslSocketFactory = sslContext.socketFactory
        
        // Set client certificate if configured
        clientCertManager.createSSLSocketFactory()?.let { sslSocketFactory ->
            conn.sslSocketFactory = sslSocketFactory
        }
        
        // Set hostname verifier
        conn.hostnameVerifier = if (config.trustAllHosts) {
            HostnameVerifier { _, _ -> true }
        } else {
            HostnameVerifier { hostname, session ->
                val cert = session.peerCertificates[0] as X509Certificate
                val sans = cert.getSubjectAlternativeNames()
                if (sans != null) {
                    for (san in sans) {
                        val type = san[0] as Int
                        val value = san[1] as String
                        if ((type == 2 && value.equals(hostname, ignoreCase = true)) || // DNS
                            (type == 7 && value == hostname)) { // IP
                            return@HostnameVerifier true
                        }
                    }
                }
                false
            }
        }
        
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

    fun test(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()
        
        try {
            val url = parseAndValidateUrl(config.url)
            val connection = setupConnection(url)
            connection.connect()
            
            result["status"] = "success"
            result["httpStatus"] = connection.responseCode
            result["cipherSuite"] = connection.cipherSuite
            
            val certificates = connection.serverCertificates
            if (certificates != null) {
                result["certificates"] = certificates.map { cert ->
                    val x509Cert = cert as X509Certificate
                    mapOf(
                        "subjectDN" to x509Cert.subjectX500Principal.name,
                        "issuerDN" to x509Cert.issuerX500Principal.name,
                        "version" to x509Cert.version,
                        "serialNumber" to x509Cert.serialNumber.toString(16),
                        "validFrom" to x509Cert.notBefore.toString(),
                        "validUntil" to x509Cert.notAfter.toString(),
                        "signatureAlgorithm" to x509Cert.sigAlgName,
                        "publicKeyAlgorithm" to x509Cert.publicKey.algorithm
                    )
                }
            }
            
            return result
        } catch (e: Exception) {
            result["status"] = "error"
            result["error"] = e.message ?: "Unknown error"
            result["errorCause"] = e.cause?.message ?: ""
            result["exitCode"] = 1
            return result
        }
    }
}
