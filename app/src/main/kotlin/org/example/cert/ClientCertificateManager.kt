package org.example.cert

import org.example.config.SSLTestConfig
import org.slf4j.LoggerFactory
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

/**
 * Manages client certificates for SSL/TLS connections.
 * Handles loading and configuring client certificates and private keys.
 */
class ClientCertificateManager(private val config: SSLTestConfig) {
    private val logger = LoggerFactory.getLogger(ClientCertificateManager::class.java)

    /**
     * Creates an SSLSocketFactory configured with the client certificate if specified.
     * @return SSLSocketFactory configured with client certificate, or null if no client certificate is specified
     */
    fun createSSLSocketFactory(): SSLSocketFactory? {
        if (config.clientCertFile == null || config.clientKeyFile == null) {
            return null
        }

        try {
            // Load client certificate
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(FileInputStream(config.clientCertFile)) as X509Certificate

            // Create a temporary keystore
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, null)
            keyStore.setKeyEntry(
                "client",
                loadPrivateKey(),
                config.clientKeyPassword?.toCharArray() ?: "".toCharArray(),
                arrayOf(cert)
            )

            // Initialize KeyManagerFactory
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, config.clientKeyPassword?.toCharArray() ?: "".toCharArray())

            // Create SSLContext
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(kmf.keyManagers, null, null)

            return sslContext.socketFactory
        } catch (e: Exception) {
            logger.error("Failed to create SSLSocketFactory with client certificate", e)
            return null
        }
    }

    private fun loadPrivateKey(): java.security.PrivateKey {
        // Implementation depends on the key format (PEM, DER, etc.)
        // For now, we'll throw an UnsupportedOperationException
        throw UnsupportedOperationException("Private key loading not implemented yet")
    }
} 