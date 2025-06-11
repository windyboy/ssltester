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
            socket = socketFactory.createSocket(url.host, 443) as SSLSocket
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
            val sslSession = socket.session ?: return false

            val peerCerts = try {
                sslSession.peerCertificates
            } catch (e: Exception) {
                logger.error("Failed to obtain peer certificates: {}", e.message)
                return false
            }

            if (peerCerts.isEmpty()) return false

            val leaf = peerCerts[0] as? X509Certificate ?: return false

            // Check SANs first
            leaf.subjectAlternativeNames?.forEach { san ->
                val type = san[0] as? Int ?: return@forEach
                if (type == 2) { // DNS name
                    val dnsName = san[1] as? String ?: return@forEach
                    if (matchesHostname(hostname, dnsName)) return true
                }
            }

            // Fall back to common name
            val cn = extractCN(leaf.subjectX500Principal.name)
            return cn != null && matchesHostname(hostname, cn)
        } catch (e: Exception) {
            logger.error("Hostname verification failed: {}", e.message)
            false
        }
    }

    private fun matchesHostname(hostname: String, pattern: String): Boolean {
        return if (pattern.startsWith("*.") && hostname.contains('.')) {
            val domain = pattern.substring(2)
            hostname.lowercase().endsWith(".$domain")
        } else {
            hostname.equals(pattern, ignoreCase = true)
        }
    }

    private fun extractCN(dn: String): String? {
        val regex = Regex("CN=([^,]+)")
        return regex.find(dn)?.groupValues?.get(1)
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