package org.example.ssl

import org.example.cert.CertificateValidator
import org.example.cert.ClientCertificateManager
import org.example.config.SSLTestConfig
import org.example.model.SSLTestResult
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import java.security.cert.X509Certificate
import org.junit.jupiter.api.Assertions.*

class SSLConnectionTesterImplTest {
    private lateinit var sslConnectionTester: SSLConnectionTesterImpl
    private lateinit var mockCertificateValidator: CertificateValidator
    private lateinit var mockClientCertificateManager: ClientCertificateManager
    private lateinit var mockCertificate: X509Certificate

    @BeforeEach
    fun setup() {
        mockCertificateValidator = mock()
        mockClientCertificateManager = mock()
        mockCertificate = mock()
        sslConnectionTester = SSLConnectionTesterImpl(
            certificateValidator = mockCertificateValidator,
            clientCertificateManager = mockClientCertificateManager
        )
    }

    @Test
    fun `test validate certificate chain`() {
        // Given
        val certificates = arrayOf(mockCertificate)
        val hostname = "example.com"
        `when`(mockCertificateValidator.validateCertificateChain(certificates, hostname)).thenReturn(true)

        // When/Then
        sslConnectionTester.validateCertificateChain(certificates, hostname)
        verify(mockCertificateValidator).validateCertificateChain(certificates, hostname)
    }

    @Test
    fun `test validate certificate chain with expired certificate`() {
        // Given
        val certificates = arrayOf(mockCertificate)
        val hostname = "example.com"
        `when`(mockCertificateValidator.validateCertificateChain(certificates, hostname)).thenReturn(false)

        // When/Then
        sslConnectionTester.validateCertificateChain(certificates, hostname)
        verify(mockCertificateValidator).validateCertificateChain(certificates, hostname)
    }

    @Test
    fun `test verify hostname`() {
        // Given
        val hostname = "example.com"
        `when`(mockCertificateValidator.verifyHostname(mockCertificate, hostname)).thenReturn(true)

        // When
        val result = sslConnectionTester.verifyHostname(mockCertificate, hostname)
        assertTrue(result)
        verify(mockCertificateValidator).verifyHostname(mockCertificate, hostname)
    }
} 