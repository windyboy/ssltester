package org.example.cert

import org.example.model.ValidationResult
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import java.security.cert.X509Certificate
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.util.Date
import java.util.HashSet
import org.junit.jupiter.api.Assertions.*
import java.math.BigInteger
import java.security.PublicKey
import javax.security.auth.x500.X500Principal
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.util.Calendar
import org.junit.jupiter.api.Disabled

class CertificateValidatorImplTest {
    private lateinit var certificateValidator: CertificateValidatorImpl
    private lateinit var mockCertificate: X509Certificate
    private lateinit var mockRootCertificate: X509Certificate
    private lateinit var mockX500Principal: X500Principal
    private lateinit var mockPublicKey: PublicKey

    @BeforeEach
    fun setup() {
        // Set test mode
        System.setProperty("test.mode", "true")
        
        mockCertificate = mock(X509Certificate::class.java)
        mockRootCertificate = mock(X509Certificate::class.java)
        mockX500Principal = mock(X500Principal::class.java)
        mockPublicKey = mock(PublicKey::class.java)
        certificateValidator = CertificateValidatorImpl()

        // Common stubs for both certificates
        val commonStubs = { cert: X509Certificate ->
            `when`(cert.notBefore).thenReturn(Date(System.currentTimeMillis() - 86400000)) // 1 day ago
            `when`(cert.notAfter).thenReturn(Date(System.currentTimeMillis() + 86400000)) // 1 day from now
            `when`(cert.serialNumber).thenReturn(BigInteger.ONE)
            `when`(cert.version).thenReturn(3)
            `when`(cert.sigAlgName).thenReturn("SHA256withRSA")
            `when`(cert.publicKey).thenReturn(mockPublicKey)
            `when`(cert.subjectAlternativeNames).thenReturn(listOf(listOf(2, "test.example.com")))
            `when`(cert.getSubjectAlternativeNames()).thenReturn(listOf(listOf(2, "test.example.com")))
            `when`(cert.issuerX500Principal).thenReturn(mockX500Principal)
            `when`(cert.subjectX500Principal).thenReturn(mockX500Principal)
            `when`(mockX500Principal.name).thenReturn("CN=test.example.com")
            `when`(cert.encoded).thenReturn(ByteArray(100) { 0 }) // Mock encoded form
        }

        commonStubs(mockCertificate)
        commonStubs(mockRootCertificate)
    }

    private fun loadCertificate(resourcePath: String): X509Certificate {
        val certFactory = CertificateFactory.getInstance("X.509")
        val inputStream: InputStream = this::class.java.classLoader.getResourceAsStream(resourcePath)
            ?: throw IllegalArgumentException("Resource not found: $resourcePath")
        return certFactory.generateCertificate(inputStream) as X509Certificate
    }

    @Test
    fun `test valid certificate chain with revocation check disabled`() {
        // Given
        val config = CertificateValidationConfig(enableRevocationCheck = false)
        val validator = CertificateValidatorImpl(config)
        val leafCert = loadCertificate("certs/leaf.der")
        val rootCert = loadCertificate("certs/root.der")
        val certificateChain = arrayOf(leafCert, rootCert)

        // When
        val result = validator.validateCertificateChain(certificateChain, "example.com")

        // Then
        assertTrue(result)
    }


    @Test
    fun `test certificate validation with custom key size requirements`() {
        // Given
        val config = CertificateValidationConfig(minRSAKeySize = 4096, minECKeySize = 384)
        val validator = CertificateValidatorImpl(config)
        val leafCert = loadCertificate("certs/leaf.der")
        val rootCert = loadCertificate("certs/root.der")
        val certificates = listOf(leafCert, rootCert)

        // When
        val result = validator.validateCertificates(certificates, "example.com")

        // Then
        assertFalse(result.chainValidationResult)
        assertTrue(result.message.contains("key size too small"))
    }

    @Test
    fun `test certificate validation with OCSP check disabled`() {
        // Given
        val config = CertificateValidationConfig(enableOCSPCheck = false)
        val validator = CertificateValidatorImpl(config)
        val leafCert = loadCertificate("certs/leaf.der")
        val rootCert = loadCertificate("certs/root.der")
        val certificates = listOf(leafCert, rootCert)

        // When
        val result = validator.validateCertificates(certificates, "example.com")

        // Then
        assertTrue(result.ocspResult) // Should be true when OCSP check is disabled
    }

    @Test
    fun `test expired certificate chain`() {
        // Given
        val notBefore = Date(System.currentTimeMillis() - 172800000) // 2 days ago
        val notAfter = Date(System.currentTimeMillis() - 86400000) // 1 day ago
        val subjectAltNames = listOf(listOf(2, "example.com"))
        val serial = BigInteger.ONE
        val version = 3
        val sigAlg = "SHA256withRSA"
        
        // Stubs for mockCertificate
        `when`(mockCertificate.notBefore).thenReturn(notBefore)
        `when`(mockCertificate.notAfter).thenReturn(notAfter)
        `when`(mockCertificate.serialNumber).thenReturn(serial)
        `when`(mockCertificate.version).thenReturn(version)
        `when`(mockCertificate.sigAlgName).thenReturn(sigAlg)
        `when`(mockCertificate.publicKey).thenReturn(mockPublicKey)
        `when`(mockCertificate.subjectAlternativeNames).thenReturn(subjectAltNames)
        `when`(mockCertificate.issuerX500Principal).thenReturn(mockX500Principal)
        `when`(mockCertificate.subjectX500Principal).thenReturn(mockX500Principal)
        `when`(mockX500Principal.name).thenReturn("CN=example.com")
        
        // Stubs for mockRootCertificate
        `when`(mockRootCertificate.notBefore).thenReturn(notBefore)
        `when`(mockRootCertificate.notAfter).thenReturn(notAfter)
        `when`(mockRootCertificate.serialNumber).thenReturn(serial)
        `when`(mockRootCertificate.version).thenReturn(version)
        `when`(mockRootCertificate.sigAlgName).thenReturn(sigAlg)
        `when`(mockRootCertificate.publicKey).thenReturn(mockPublicKey)
        `when`(mockRootCertificate.subjectAlternativeNames).thenReturn(subjectAltNames)
        `when`(mockRootCertificate.issuerX500Principal).thenReturn(mockX500Principal)
        `when`(mockRootCertificate.subjectX500Principal).thenReturn(mockX500Principal)
        
        val certificateChain = arrayOf(mockCertificate, mockRootCertificate)
        // When
        val result = certificateValidator.validateCertificateChain(certificateChain, "example.com")
        // Then
        assertFalse(result)
    }

    @Test
    fun `test hostname verification`() {
        // Given
        `when`(mockCertificate.subjectAlternativeNames).thenReturn(listOf(listOf(2, "test.example.com")))

        // When
        val result = certificateValidator.verifyHostname(mockCertificate, "test.example.com")

        // Then
        assertTrue(result)
    }

    @Test
    fun `test hostname verification with wildcard`() {
        // Given
        `when`(mockCertificate.subjectAlternativeNames).thenReturn(listOf(listOf(2, "*.example.com")))

        // When
        val result = certificateValidator.verifyHostname(mockCertificate, "test.example.com")

        // Then
        assertTrue(result)
    }

    @Test
    fun `test hostname verification with invalid hostname`() {
        // Given
        `when`(mockCertificate.subjectAlternativeNames).thenReturn(listOf(listOf(2, "test.example.com")))

        // When
        val result = certificateValidator.verifyHostname(mockCertificate, "invalid.example.com")

        // Then
        assertFalse(result)
    }
} 