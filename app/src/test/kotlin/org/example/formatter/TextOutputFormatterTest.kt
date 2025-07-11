package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import java.util.Date
import javax.security.auth.x500.X500Principal

class TextOutputFormatterTest {
    private lateinit var formatter: TextOutputFormatter
    private lateinit var mockCertificate: X509Certificate

    @BeforeEach
    fun setUp() {
        formatter = TextOutputFormatter()
        mockCertificate = createMockCertificate("CN=example.com")
    }

    @Test
    fun testFormatWithValidSSLConnection() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(150),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)

        assertTrue(result.contains("example.com"))
        assertTrue(result.contains("443"))
        assertTrue(result.contains("TLSv1.3"))
        assertTrue(result.contains("TLS_AES_256_GCM_SHA384"))
        assertTrue(result.contains("150ms"))
        assertTrue(result.contains("✓ Secure"))
        assertTrue(result.contains("Certificate Chain"))
    }

    @Test
    fun testFormatWithInsecureConnection() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.2",
                cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA",
                handshakeTime = Duration.ofMillis(200),
                isSecure = false,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createInvalidValidationResult(),
            )

        val result = formatter.format(connection)

        assertTrue(result.contains("✗ Not Secure"))
        assertTrue(result.contains("Issues:"))
        assertTrue(result.contains("Certificate expired"))
    }

    @Test
    fun testFormatWithEmptyCertificateChain() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = emptyList(),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)

        assertTrue(result.contains("Certificate Chain: Empty"))
    }

    @Test
    fun testFormatWithMultipleCertificates() {
        val cert1 = createMockCertificate("CN=leaf.example.com")
        val cert2 = createMockCertificate("CN=intermediate.ca.com")
        val cert3 = createMockCertificate("CN=root.ca.com")

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(120),
                isSecure = true,
                certificateChain = listOf(cert1, cert2, cert3),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        
        // Debug: print the actual output
        println("=== ACTUAL OUTPUT ===")
        println(result)
        println("=== END OUTPUT ===")

        assertTrue(result.contains("Certificate 1"))
        assertTrue(result.contains("Certificate 2"))
        assertTrue(result.contains("Certificate 3"))
        assertTrue(result.contains("leaf.example.com"))
        assertTrue(result.contains("intermediate.ca.com"))
        assertTrue(result.contains("root.ca.com"))
    }

    @Test
    fun testFormatWithWarnings() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = listOf("Certificate expires in 15 days"),
                daysUntilExpiry = 15,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.MEDIUM,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)

        assertTrue(result.contains("Warnings:"))
        assertTrue(result.contains("Certificate expires in 15 days"))
    }

    @Test
    fun testFormatWithMultipleIssues() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = false,
                issues = listOf("Certificate expired", "Hostname mismatch", "Weak key size"),
                warnings = emptyList(),
                daysUntilExpiry = -5,
                isHostnameValid = false,
                certificateStrength = CertificateValidator.CertificateStrength.WEAK,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.2",
                cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA",
                handshakeTime = Duration.ofMillis(300),
                isSecure = false,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)

        assertTrue(result.contains("Issues:"))
        assertTrue(result.contains("Certificate expired"))
        assertTrue(result.contains("Hostname mismatch"))
        assertTrue(result.contains("Weak key size"))
        assertTrue(result.contains("WEAK"))
    }

    @Test
    fun testFormatWithDifferentCertificateStrengths() {
        val strengths =
            listOf(
                CertificateValidator.CertificateStrength.WEAK,
                CertificateValidator.CertificateStrength.MEDIUM,
                CertificateValidator.CertificateStrength.STRONG,
            )

        strengths.forEach { strength ->
            val validationResult =
                CertificateValidator.ValidationResult(
                    isValid = true,
                    issues = emptyList(),
                    warnings = emptyList(),
                    daysUntilExpiry = 100,
                    isHostnameValid = true,
                    certificateStrength = strength,
                )

            val connection =
                createTestConnection(
                    host = "example.com",
                    port = 443,
                    protocol = "TLSv1.3",
                    cipherSuite = "TLS_AES_256_GCM_SHA384",
                    handshakeTime = Duration.ofMillis(100),
                    isSecure = true,
                    certificateChain = listOf(mockCertificate),
                    certificateValidation = validationResult,
                )

            val result = formatter.format(connection)
            assertTrue(result.contains(strength.name))
        }
    }

    @Test
    fun testFormatWithVeryLongHostname() {
        val longHostname = "very-long-hostname-that-exceeds-normal-length.example.com"
        val connection =
            createTestConnection(
                host = longHostname,
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains(longHostname))
    }

    @Test
    fun testFormatWithVeryLongCipherSuite() {
        val longCipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_P384"
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = longCipherSuite,
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains(longCipherSuite))
    }

    @Test
    fun testFormatWithVerySlowHandshake() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(5000),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("5000ms"))
    }

    @Test
    fun testFormatWithNullCertificateValidation() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = null,
            )

        val result = formatter.format(connection)
        assertFalse(result.contains("Certificate Validation"))
    }

    @Test
    fun testFormatWithErrorInCertificateFormatting() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun testFormatWithSpecialCharactersInHostname() {
        val specialHostname = "test-host.example.com"
        val connection =
            createTestConnection(
                host = specialHostname,
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains(specialHostname))
    }

    @Test
    fun testFormatWithIPv4Address() {
        val connection =
            createTestConnection(
                host = "192.168.1.1",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("192.168.1.1"))
    }

    @Test
    fun testFormatWithIPv6Address() {
        val connection =
            createTestConnection(
                host = "::1",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("::1"))
    }

    @Test
    fun testFormatWithNonStandardPort() {
        val connection =
            createTestConnection(
                host = "example.com",
                port = 8443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = createValidValidationResult(),
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("8443"))
    }

    @Test
    fun testFormatWithExpiredCertificate() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = false,
                issues = listOf("Certificate expired"),
                warnings = emptyList(),
                daysUntilExpiry = -10,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.WEAK,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = false,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("Certificate expired"))
        assertTrue(result.contains("-10 days"))
    }

    @Test
    fun testFormatWithExpiringSoonCertificate() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = listOf("Certificate expires soon"),
                daysUntilExpiry = 5,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.MEDIUM,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("5 days"))
    }

    @Test
    fun testFormatWithStrongCertificate() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 365,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.STRONG,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("365 days"))
        assertTrue(result.contains("STRONG"))
    }

    @Test
    fun testFormatWithHostnameMismatch() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = false,
                issues = listOf("Hostname mismatch"),
                warnings = emptyList(),
                daysUntilExpiry = 100,
                isHostnameValid = false,
                certificateStrength = CertificateValidator.CertificateStrength.MEDIUM,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = false,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("Hostname mismatch"))
        assertTrue(result.contains("✗ Hostname verification failed"))
    }

    @Test
    fun testFormatWithValidHostname() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 100,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.STRONG,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("✓ Hostname verification passed"))
    }

    @Test
    fun testFormatWithUnknownCertificateStrength() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 100,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.UNKNOWN,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("UNKNOWN"))
    }

    @Test
    fun testFormatWithMultipleWarnings() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = listOf("Certificate expires in 15 days", "Weak key size"),
                daysUntilExpiry = 15,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.MEDIUM,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("Certificate expires in 15 days"))
        assertTrue(result.contains("Weak key size"))
    }

    @Test
    fun testFormatWithNoIssuesOrWarnings() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 365,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.STRONG,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertFalse(result.contains("Issues:"))
        assertFalse(result.contains("Warnings:"))
    }

    @Test
    fun testFormatWithNullDaysUntilExpiry() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = null,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.STRONG,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertFalse(result.contains("Days until expiry:"))
    }

    @Test
    fun testFormatWithNullCertificateStrength() {
        val validationResult =
            CertificateValidator.ValidationResult(
                isValid = true,
                issues = emptyList(),
                warnings = emptyList(),
                daysUntilExpiry = 100,
                isHostnameValid = true,
                certificateStrength = CertificateValidator.CertificateStrength.UNKNOWN,
            )

        val connection =
            createTestConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation = validationResult,
            )

        val result = formatter.format(connection)
        assertTrue(result.contains("UNKNOWN"))
    }

    @Test
    fun testGetFileExtension() {
        assertEquals("txt", formatter.getFileExtension())
    }

    private fun createTestConnection(
        host: String,
        port: Int,
        protocol: String,
        cipherSuite: String,
        handshakeTime: Duration,
        isSecure: Boolean,
        certificateChain: List<X509Certificate>,
        certificateValidation: CertificateValidator.ValidationResult?,
    ): SSLConnection {
        return SSLConnection(
            host = host,
            port = port,
            protocol = protocol,
            cipherSuite = cipherSuite,
            handshakeTime = handshakeTime,
            isSecure = isSecure,
            certificateChain = certificateChain,
            certificateValidation = certificateValidation,
        )
    }

    private fun createMockCertificate(subject: String): X509Certificate {
        return object : X509Certificate() {
            override fun getVersion(): Int = 3
            override fun getSerialNumber(): java.math.BigInteger = java.math.BigInteger.ONE
            override fun getIssuerDN(): java.security.Principal = X500Principal("CN=Test CA")
            override fun getSubjectDN(): java.security.Principal = X500Principal(subject)
            override fun getNotBefore(): java.util.Date = java.util.Date()
            override fun getNotAfter(): java.util.Date = java.util.Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L)
            override fun getTBSCertificate(): ByteArray = ByteArray(0)
            override fun getSignature(): ByteArray = ByteArray(0)
            override fun getSigAlgName(): String = "SHA256withRSA"
            override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"
            override fun getSigAlgParams(): ByteArray? = null
            override fun getIssuerUniqueID(): BooleanArray? = null
            override fun getSubjectUniqueID(): BooleanArray? = null
            override fun getKeyUsage(): BooleanArray? = null
            override fun getExtendedKeyUsage(): MutableList<String>? = null
            override fun getBasicConstraints(): Int = -1
            override fun getEncoded(): ByteArray = ByteArray(0)
            override fun verify(key: java.security.PublicKey) {}
            override fun verify(key: java.security.PublicKey, sigProvider: String) {}
            override fun getCriticalExtensionOIDs(): MutableSet<String>? = null
            override fun getExtensionValue(oid: String): ByteArray? = null
            override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null
            override fun hasUnsupportedCriticalExtension(): Boolean = false
            override fun checkValidity() {}
            override fun checkValidity(date: java.util.Date) {}
            override fun toString(): String = "MockCertificate"
            override fun getPublicKey(): java.security.PublicKey = object : java.security.PublicKey {
                override fun getAlgorithm(): String = "RSA"
                override fun getFormat(): String = "X.509"
                override fun getEncoded(): ByteArray = ByteArray(0)
            }
            override fun getSubjectX500Principal(): X500Principal = X500Principal(subject)
            override fun getIssuerX500Principal(): X500Principal = X500Principal("CN=Test CA")
        }
    }

    private fun createValidValidationResult(): CertificateValidator.ValidationResult {
        return CertificateValidator.ValidationResult(
            isValid = true,
            issues = emptyList(),
            warnings = emptyList(),
            daysUntilExpiry = 365,
            isHostnameValid = true,
            certificateStrength = CertificateValidator.CertificateStrength.STRONG,
        )
    }

    private fun createInvalidValidationResult(): CertificateValidator.ValidationResult {
        return CertificateValidator.ValidationResult(
            isValid = false,
            issues = listOf("Certificate expired"),
            warnings = emptyList(),
            daysUntilExpiry = -10,
            isHostnameValid = false,
            certificateStrength = CertificateValidator.CertificateStrength.WEAK,
        )
    }
}
