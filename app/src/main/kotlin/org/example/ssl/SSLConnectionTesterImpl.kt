package org.example.ssl

import org.example.exception.SSLTestException
import org.example.cert.CertificateValidator
import org.example.cert.ClientCertificateManager
import org.example.config.SSLTestConfig
import org.example.model.SSLTestResult
import org.example.model.ValidationResult
import org.slf4j.LoggerFactory
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.*
import java.util.concurrent.TimeUnit

/**
 * Implementation of SSL connection testing with enhanced security features.
 */
class SSLConnectionTesterImpl(
    private val certificateValidator: CertificateValidator,
    private val clientCertificateManager: ClientCertificateManager
) : SSLConnectionTester {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun testConnection(config: SSLTestConfig): SSLTestResult {
        var connection: HttpsURLConnection? = null
        try {
            val url = URL(config.url)
            connection = url.openConnection() as HttpsURLConnection

            // Configure connection with timeouts
            connection.connectTimeout = config.connectTimeout
            connection.readTimeout = config.readTimeout
            connection.instanceFollowRedirects = true

            // Configure SSL with modern protocols
            val sslContext = clientCertificateManager.createSSLContext(config)
            val trustManagers = clientCertificateManager.createTrustManagers(config)
            sslContext.init(null, trustManagers, null)
            
            // Set modern TLS protocols
            val sslParameters = sslContext.defaultSSLParameters
            sslParameters.protocols = arrayOf("TLSv1.2", "TLSv1.3")
            sslParameters.cipherSuites = getSecureCipherSuites()
            connection.sslSocketFactory = sslContext.socketFactory

            // Configure hostname verification
            if (!config.verifyHostname) {
                connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
            }

            // Connect and get certificates
            connection.connect()
            val serverCertificates = connection.serverCertificates
                .filterIsInstance<X509Certificate>()

            // Validate certificates with timeout
            val validationResult = withTimeout(config.connectTimeout.toLong()) {
                certificateValidator.validateCertificates(
                    serverCertificates,
                    url.host
                )
            }

            return SSLTestResult(
                hostname = url.host,
                port = url.port.takeIf { it != -1 } ?: url.defaultPort,
                protocol = connection.cipherSuite.split("_").first(),
                cipherSuite = connection.cipherSuite,
                certificateChain = serverCertificates,
                validationResult = validationResult
            )
        } catch (e: SSLHandshakeException) {
            logger.error("SSL handshake failed: ${e.message}", e)
            throw SSLTestException("SSL handshake failed: ${e.message}")
        } catch (e: java.net.SocketTimeoutException) {
            logger.error("Connection timeout: ${e.message}", e)
            throw SSLTestException("Connection timeout: ${e.message}")
        } catch (e: Exception) {
            logger.error("Failed to test SSL connection: ${e.message}", e)
            throw SSLTestException("Failed to test SSL connection: ${e.message}")
        } finally {
            connection?.disconnect()
        }
    }

    override fun validateCertificateChain(certificates: Array<X509Certificate>, hostname: String) {
        certificateValidator.validateCertificateChain(certificates, hostname)
    }

    override fun verifyHostname(certificate: X509Certificate, hostname: String): Boolean {
        return certificateValidator.verifyHostname(certificate, hostname)
    }

    private fun getSecureCipherSuites(): Array<String> {
        return arrayOf(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        )
    }

    private fun <T> withTimeout(timeoutMillis: Long, block: () -> T): T {
        val startTime = System.currentTimeMillis()
        val result = block()
        val elapsedTime = System.currentTimeMillis() - startTime
        
        if (elapsedTime > timeoutMillis) {
            throw SSLTestException("Operation timed out after ${elapsedTime}ms")
        }
        
        return result
    }
} 