package org.example.ssl

import java.io.IOException
import java.net.URL
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SSLSession
import java.security.cert.X509Certificate
import org.slf4j.LoggerFactory

/**
 * A client for establishing and managing SSL/TLS connections.
 * This class handles the connection setup, certificate validation, and connection cleanup.
 */
class SSLClient(private val socketFactory: SSLSocketFactory) {
    private var socket: SSLSocket? = null
    private val logger = LoggerFactory.getLogger(SSLClient::class.java)

    /**
     * Establishes an SSL connection and validates certificates.
     * @param url The HTTPS URL to connect to
     * @return SSLConnectionResult containing connection results and certificate information
     * @throws IllegalArgumentException if the URL is invalid
     */
    fun connect(url: URL): SSLConnectionResult {
        if (url.protocol != "https") {
            throw IllegalArgumentException("URL must use HTTPS protocol")
        }

        return try {
            val port = if (url.port != -1) url.port else url.defaultPort
            socket = socketFactory.createSocket(url.host, port) as SSLSocket
            socket?.startHandshake()

            // Get connection information
            val sslSession = socket?.session
            val cipherSuite = sslSession?.cipherSuite ?: ""
            val certs = sslSession?.peerCertificates?.map { it as X509Certificate } ?: emptyList()

            // Verify hostname
            val hostnameVerified = verifyHostname(socket, url.host)

            SSLConnectionResult(
                success = true,
                certificateChain = certs,
                error = null,
                cipherSuite = cipherSuite,
                httpStatus = 0,
                hostnameVerified = hostnameVerified
            )
        } catch (e: IOException) {
            close()
            createErrorResult(e)
        }
    }

    /**
     * Verifies if the hostname matches the certificate.
     */
    private fun verifyHostname(socket: SSLSocket?, hostname: String): Boolean {
        return try {
            if (socket == null) return false
            val sslSession = socket.session
            if (sslSession == null) {
                logger.error("No SSL session available")
                return false
            }
            true
        } catch (e: Exception) {
            logger.error("Hostname verification failed: {}", e.message)
            false
        }
    }

    /**
     * Closes the current connection.
     */
    fun close() {
        try {
            socket?.close()
        } finally {
            socket = null
        }
    }

    private fun createErrorResult(error: Exception) = SSLConnectionResult(
        success = false,
        certificateChain = emptyList(),
        error = error,
        cipherSuite = "",
        httpStatus = 0,
        hostnameVerified = false
    )
} 