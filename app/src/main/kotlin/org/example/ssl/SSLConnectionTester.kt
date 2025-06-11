package org.example.ssl

import org.example.config.SSLTestConfig
import org.example.model.SSLTestResult
import java.net.URL
import java.security.cert.X509Certificate

/**
 * Interface for SSL connection testing functionality.
 */
interface SSLConnectionTester {
    /**
     * Tests the SSL connection using the provided configuration.
     * @param config The SSL test configuration
     * @return The test result
     */
    fun testConnection(config: SSLTestConfig): SSLTestResult

    /**
     * Validates the server's certificate chain.
     *
     * @param certificates The certificate chain to validate
     * @param hostname The hostname to validate against
     * @throws SSLTestException if validation fails
     */
    fun validateCertificateChain(certificates: Array<X509Certificate>, hostname: String)

    /**
     * Verifies the hostname against the server certificate.
     *
     * @param certificate The server certificate
     * @param hostname The hostname to verify
     * @return true if the hostname is valid, false otherwise
     */
    fun verifyHostname(certificate: X509Certificate, hostname: String): Boolean
} 