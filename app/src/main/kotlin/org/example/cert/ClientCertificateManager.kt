package org.example.cert

import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import java.io.File
import java.security.cert.Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.net.ssl.X509KeyManager

/**
 * Interface for managing client certificates and SSL context.
 */
interface ClientCertificateManager {
    /**
     * Creates an SSL socket factory for the given configuration.
     * @param config The SSL test configuration
     * @return The configured SSL socket factory
     */
    fun createSSLSocketFactory(config: SSLTestConfig): SSLSocketFactory

    /**
     * Creates an SSL context for the given configuration.
     * @param config The SSL test configuration
     * @return The configured SSL context
     */
    fun createSSLContext(config: SSLTestConfig): SSLContext

    /**
     * Creates trust managers for the given configuration.
     * @param config The SSL test configuration
     * @return Array of trust managers
     */
    fun createTrustManagers(config: SSLTestConfig): Array<TrustManager>

    /**
     * Creates a custom trust manager that accepts all certificates.
     * @return A trust manager that accepts all certificates
     */
    fun createTrustAllManager(): X509TrustManager

    /**
     * Creates key managers for client certificate authentication.
     * @param config The SSL test configuration
     * @return Array of key managers
     * @throws SSLTestException if the certificate configuration is invalid
     */
    fun createKeyManagers(config: SSLTestConfig): Array<X509KeyManager>

    /**
     * Loads a client certificate from the specified files.
     * @param certFile The certificate file
     * @param keyFile The private key file
     * @param password The password for the private key
     * @return The loaded certificate
     * @throws SSLTestException if the certificate cannot be loaded
     */
    fun loadClientCertificate(certFile: File, keyFile: File, password: String?): Certificate

    /**
     * Validates the client certificate configuration.
     * @param config The SSL test configuration
     * @throws SSLTestException if the configuration is invalid
     */
    fun validateConfiguration(config: SSLTestConfig)
}