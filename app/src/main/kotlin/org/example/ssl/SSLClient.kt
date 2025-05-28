package org.example.ssl

import org.slf4j.LoggerFactory
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SSLSession
import java.security.cert.X509Certificate

/**
 * A client for establishing and managing SSL/TLS connections.
 * This class handles the connection setup, certificate validation, and connection cleanup.
 */
class SSLClient(
    private val connectTimeout: Int = DEFAULT_TIMEOUT,
    private val readTimeout: Int = DEFAULT_TIMEOUT,
    private val followRedirects: Boolean = false,
    private val sslSocketFactory: SSLSocketFactory? = null
) {
    private var currentConnection: HttpsURLConnection? = null

    /**
     * Establishes an SSL connection and validates certificates.
     * @param url The HTTPS URL to connect to
     * @return SSLConnectionResult containing connection results and certificate information
     * @throws IllegalArgumentException if the URL is invalid
     */
    fun connect(url: URL): SSLConnectionResult {
        if (url.protocol.lowercase() != "https") {
            throw IllegalArgumentException("URL must use HTTPS protocol")
        }

        return try {
            logger.info("Connecting to {}...", url)
            currentConnection = url.openConnection() as HttpsURLConnection

            // Configure connection
            currentConnection?.apply {
                this.connectTimeout = this@SSLClient.connectTimeout
                this.readTimeout = this@SSLClient.readTimeout
                this.instanceFollowRedirects = this@SSLClient.followRedirects
                sslSocketFactory?.let { this.sslSocketFactory = it }
            }

            // Establish connection
            currentConnection?.connect()

            // Get connection information
            val responseCode = currentConnection?.responseCode ?: 0
            val cipherSuite = currentConnection?.cipherSuite ?: ""
            val certs = currentConnection?.serverCertificates?.map { it as X509Certificate } ?: emptyList()

            // Verify hostname
            val hostnameVerified = verifyHostname(currentConnection, url.host)

            SSLConnectionResult(
                success = true,
                certificateChain = certs,
                error = null,
                cipherSuite = cipherSuite,
                httpStatus = responseCode,
                hostnameVerified = hostnameVerified
            )

        } catch (e: javax.net.ssl.SSLHandshakeException) {
            logger.error("SSL handshake failed: {}", e.message)
            createErrorResult(e)
        } catch (e: java.net.SocketTimeoutException) {
            logger.error("Connection timeout: {}", e.message)
            createErrorResult(e)
        } catch (e: Exception) {
            logger.error("Connection failed: {}", e.message)
            createErrorResult(e)
        }
    }

    /**
     * Verifies if the hostname matches the certificate.
     */
    private fun verifyHostname(conn: HttpsURLConnection?, hostname: String): Boolean {
        return try {
            if (conn == null) return false
            val sslSession = try {
                val method = conn.javaClass.getMethod("getSslSession")
                val result = method.invoke(conn)
                when (result) {
                    is javax.net.ssl.SSLSession -> result
                    is java.util.Optional<*> -> result.orElse(null) as? javax.net.ssl.SSLSession
                    else -> null
                }
            } catch (e: Exception) {
                // fallback for older JDKs
                try {
                    conn.sslSession
                } catch (ex: Exception) {
                    null
                }
            } as? javax.net.ssl.SSLSession
            if (sslSession == null) {
                logger.error("No SSL session available")
                return false
            }
            conn.hostnameVerifier.verify(hostname, sslSession)
        } catch (e: Exception) {
            logger.error("Hostname verification failed: {}", e.message)
            false
        }
    }

    /**
     * Closes the current connection.
     */
    fun close() {
        currentConnection?.disconnect()
        currentConnection = null
    }

    private fun createErrorResult(error: Exception) = SSLConnectionResult(
        success = false,
        certificateChain = emptyList(),
        error = error,
        cipherSuite = "",
        httpStatus = 0,
        hostnameVerified = false
    )

    companion object {
        private val logger = LoggerFactory.getLogger(SSLClient::class.java)
        private const val DEFAULT_TIMEOUT = 10000 // 10 seconds
    }
} 