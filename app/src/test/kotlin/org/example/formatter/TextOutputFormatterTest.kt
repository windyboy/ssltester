package org.example.formatter

import io.mockk.every
import io.mockk.mockk
import org.example.model.SSLConnection
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import org.example.CertificateValidator
import org.example.model.OutputFormat

class TextOutputFormatterTest {
    private val formatter = TextOutputFormatter()
    private val mockCertificate: X509Certificate = createMockCertificate()

    private fun stripAnsiCodes(text: String): String {
        return text.replace("""\u001B\[[;\d]*m""".toRegex(), "")
    }

    @Test
    fun `test format secure connection`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.serialNumber } returns BigInteger.valueOf(123456789)
        every { cert.encoded } returns "test".toByteArray()

        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(cert),
            )

        val output = stripAnsiCodes(formatter.format(connection))

        assertTrue(output.contains("SSL/TLS Connection Test Results"))
        assertTrue(output.contains("Basic Information"))
        assertTrue(output.contains("Host: example.com"))
        assertTrue(output.contains("Port: 443"))
        assertTrue(output.contains("Secure"))
        assertTrue(output.contains("Protocol Information"))
        assertTrue(output.contains("Protocol Version: TLSv1.3"))
        assertTrue(output.contains("Cipher Suite: TLS_AES_256_GCM_SHA384"))
        assertTrue(output.contains("Handshake Time: 100ms"))
        assertTrue(output.contains("Certificate Chain"))
        assertTrue(output.contains("Certificate 1"))
        assertTrue(output.contains("CN=example.com"))
        assertTrue(output.contains("CN=Test CA"))
    }

    @Test
    fun `test format insecure connection`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "Unknown (Connection failed)",
                cipherSuite = "Unknown",
                handshakeTime = Duration.ofMillis(50),
                isSecure = false,
                certificateChain = emptyList(),
            )

        val output = stripAnsiCodes(formatter.format(connection))

        assertTrue(output.contains("SSL/TLS Connection Test Results"))
        assertTrue(output.contains("Basic Information"))
        assertTrue(output.contains("Host: example.com"))
        assertTrue(output.contains("Port: 443"))
        assertTrue(output.contains("Not Secure"))
        assertTrue(output.contains("Protocol Information"))
        assertTrue(output.contains("Protocol Version: Unknown (Connection failed)"))
        assertTrue(output.contains("Cipher Suite: Unknown"))
        assertTrue(output.contains("Handshake Time: 50ms"))
        assertTrue(output.contains("Certificate Chain: Empty"))
    }

    @Test
    fun `test format with certificate error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } throws RuntimeException("Certificate error")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } returns "test".toByteArray()

        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(cert),
            )

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("Error formatting certificate"))
    }

    @Test
    fun `test format with encoding error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } throws RuntimeException("Encoding error")

        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(cert),
            )

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("Error formatting certificate"))
    }

    @Test
    fun `test getFileExtension`() {
        assertEquals("txt", formatter.getFileExtension())
    }



    @Test
    fun `test format with special characters in hostname`() {
        val connection =
            SSLConnection(
                host = "test-host.example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = emptyList(),
            )

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("test-host.example.com"))
    }

    @Test
    fun `test format with all fields populated`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("example.com"))
        assertTrue(result.contains("443"))
        assertTrue(result.contains("TLSv1.3"))
        assertTrue(result.contains("TLS_AES_256_GCM_SHA384"))
        assertTrue(result.contains("150ms"))
        assertTrue(result.contains("✓ Secure"))
        assertTrue(result.contains("Certificate Information"))
    }

    @Test
    fun `test format with insecure connection`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.2",
            cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA",
            handshakeTime = Duration.ofMillis(200),
            isSecure = false,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createInvalidValidationResult()
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("✗ Insecure"))
        assertTrue(result.contains("Issues:"))
        assertTrue(result.contains("Certificate expired"))
    }

    @Test
    fun `test format with empty certificate chain`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(100),
            isSecure = true,
            certificateChain = emptyList(),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("No certificates available"))
    }

    @Test
    fun `test format with multiple certificates`() {
        val cert1 = createMockCertificate("CN=leaf.example.com")
        val cert2 = createMockCertificate("CN=intermediate.ca.com")
        val cert3 = createMockCertificate("CN=root.ca.com")

        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(120),
            isSecure = true,
            certificateChain = listOf(cert1, cert2, cert3),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("Certificate #1"))
        assertTrue(result.contains("Certificate #2"))
        assertTrue(result.contains("Certificate #3"))
        assertTrue(result.contains("leaf.example.com"))
        assertTrue(result.contains("intermediate.ca.com"))
        assertTrue(result.contains("root.ca.com"))
    }

    @Test
    fun `test format with warnings`() {
        val validationResult = CertificateValidator.ValidationResult(
            isValid = true,
            issues = emptyList(),
            warnings = listOf("Certificate expires in 15 days"),
            daysUntilExpiry = 15,
            isHostnameValid = true,
            certificateStrength = CertificateValidator.CertificateStrength.MEDIUM
        )

        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(100),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = validationResult
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("Warnings:"))
        assertTrue(result.contains("Certificate expires in 15 days"))
    }

    @Test
    fun `test format with multiple issues`() {
        val validationResult = CertificateValidator.ValidationResult(
            isValid = false,
            issues = listOf("Certificate expired", "Hostname mismatch", "Weak key size"),
            warnings = emptyList(),
            daysUntilExpiry = -5,
            isHostnameValid = false,
            certificateStrength = CertificateValidator.CertificateStrength.WEAK
        )

        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.2",
            cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA",
            handshakeTime = Duration.ofMillis(300),
            isSecure = false,
            certificateChain = listOf(mockCertificate),
            certificateValidation = validationResult
        )

        val result = formatter.format(connection)

        assertTrue(result.contains("Issues:"))
        assertTrue(result.contains("Certificate expired"))
        assertTrue(result.contains("Hostname mismatch"))
        assertTrue(result.contains("Weak key size"))
        assertTrue(result.contains("Weak"))
    }

    @Test
    fun `test format with different certificate strengths`() {
        val strengths = listOf(
            CertificateValidator.CertificateStrength.WEAK,
            CertificateValidator.CertificateStrength.MEDIUM,
            CertificateValidator.CertificateStrength.STRONG
        )

        strengths.forEach { strength ->
            val validationResult = CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 100,
                isHostnameValid = true,
                certificateStrength = strength
            )

            val connection = createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult
            )

            val result = formatter.format(connection)
            assertTrue(result.contains(strength.name))
        }
    }

    @Test
    fun `test format with very long hostname`() {
        val longHostname = "very-long-hostname-that-exceeds-normal-length.example.com"
        val connection = createTestConnection(
            host = longHostname,
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(100),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)
        assertTrue(result.contains(longHostname))
    }

    @Test
    fun `test format with very long cipher suite`() {
        val longCipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_P384"
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = longCipherSuite,
            handshakeTime = Duration.ofMillis(100),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)
        assertTrue(result.contains(longCipherSuite))
    }

    @Test
    fun `test format with very fast handshake`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofNanos(50000000), // 50ms
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)
        assertTrue(result.contains("50ms"))
    }

    @Test
    fun `test format with very slow handshake`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofSeconds(5),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = createValidValidationResult()
        )

        val result = formatter.format(connection)
        assertTrue(result.contains("5s"))
    }

    @Test
    fun `test format with null certificate validation`() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(100),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = null
        )

        val result = formatter.format(connection)
        assertTrue(result.contains("Certificate validation not available"))
    }



    private fun createTestConnection(
        host: String,
        port: Int,
        protocol: String,
        cipherSuite: String,
        handshakeTime: Duration,
        isSecure: Boolean,
        certificateChain: List<X509Certificate>,
        certificateValidation: CertificateValidator.ValidationResult?
    ): SSLConnection {
        return SSLConnection(
            host = host,
            port = port,
            protocol = protocol,
            cipherSuite = cipherSuite,
            handshakeTime = handshakeTime,
            isSecure = isSecure,
            certificateChain = certificateChain,
            certificateValidation = certificateValidation
        )
    }

    private fun createMockCertificate(subject: String = "CN=example.com"): X509Certificate {
        return object : X509Certificate() {
            override fun getVersion(): Int = 3
            override fun getSerialNumber(): java.math.BigInteger = java.math.BigInteger.ONE
            override fun getIssuerDN(): java.security.Principal = javax.security.auth.x500.X500Principal(subject)
            override fun getSubjectDN(): java.security.Principal = javax.security.auth.x500.X500Principal(subject)
            override fun getNotBefore(): java.util.Date = java.util.Date.from(Instant.now().minus(java.time.Duration.ofDays(30)))
            override fun getNotAfter(): java.util.Date = java.util.Date.from(Instant.now().plus(java.time.Duration.ofDays(365)))
            override fun getSignature(): ByteArray = ByteArray(0)
            override fun getSigAlgName(): String = "SHA256withRSA"
            override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"
            override fun getSigAlgParams(): ByteArray? = null
            override fun getIssuerUniqueID(): BooleanArray? = null
            override fun getSubjectUniqueID(): BooleanArray? = null
            override fun getTBSCertificate(): ByteArray = ByteArray(0)
            override fun getIssuerX500Principal(): javax.security.auth.x500.X500Principal = javax.security.auth.x500.X500Principal(subject)
            override fun getSubjectX500Principal(): javax.security.auth.x500.X500Principal = javax.security.auth.x500.X500Principal(subject)
            override fun getKeyUsage(): BooleanArray? = null
            override fun getExtendedKeyUsage(): List<String>? = null
            override fun getBasicConstraints(): Int = -1
            override fun getSubjectAlternativeNames(): Collection<List<*>>? = null
            override fun getIssuerAlternativeNames(): Collection<List<*>>? = null
            override fun getCriticalExtensionOIDs(): Set<String>? = null
            override fun getExtensionValue(oid: String): ByteArray? = null
            override fun getNonCriticalExtensionOIDs(): Set<String>? = null
            override fun hasUnsupportedCriticalExtension(): Boolean = false
            override fun checkValidity() {}
            override fun checkValidity(date: java.util.Date) {}
            override fun getPublicKey(): java.security.PublicKey = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair().public
            override fun verify(key: java.security.PublicKey) {}
            override fun verify(key: java.security.PublicKey, sigProvider: String) {}
            override fun toString(): String = "MockCertificate($subject)"
            override fun getEncoded(): ByteArray = ByteArray(0)
        }
    }

    private fun createValidValidationResult(): CertificateValidator.ValidationResult {
        return CertificateValidator.ValidationResult(
            isValid = true,
            issues = emptyList(),
            warnings = emptyList(),
            daysUntilExpiry = 365,
            isHostnameValid = true,
            certificateStrength = CertificateValidator.CertificateStrength.STRONG
        )
    }

    private fun createInvalidValidationResult(): CertificateValidator.ValidationResult {
        return CertificateValidator.ValidationResult(
            isValid = false,
            issues = listOf("Certificate expired"),
            warnings = emptyList(),
            daysUntilExpiry = -5,
            isHostnameValid = false,
            certificateStrength = CertificateValidator.CertificateStrength.WEAK
        )
    }
}
