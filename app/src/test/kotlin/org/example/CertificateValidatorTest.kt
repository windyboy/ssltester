package org.example

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CertificateValidatorTest {
    private lateinit var validator: CertificateValidator
    private lateinit var keyPair: KeyPair

    @BeforeEach
    fun setUp() {
        validator = CertificateValidator()
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        keyPair = keyPairGenerator.generateKeyPair()
    }

    @Test
    fun `test validateCertificateChain with empty certificates`() {
        val result = validator.validateCertificateChain(emptyList(), "example.com")

        assertFalse(result.isValid)
        assertEquals(1, result.issues.size)
        assertTrue(result.issues.contains("No certificates provided"))
    }

    @Test
    fun `test validateCertificateChain with single certificate`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertTrue(result.isValid)
        assertTrue(result.isHostnameValid)
        assertEquals(CertificateValidator.CertificateStrength.MEDIUM, result.certificateStrength)
        assertNotNull(result.daysUntilExpiry)
        assertTrue(result.daysUntilExpiry!! > 0)
    }

    @Test
    fun `test validateCertificateChain with expired certificate`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().minus(1, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertFalse(result.isValid)
        assertEquals(1, result.issues.size)
        assertTrue(result.issues.any { it.contains("Certificate expired") })
        assertNotNull(result.daysUntilExpiry)
        assertTrue(result.daysUntilExpiry!! < 0)
    }

    @Test
    fun `test validateCertificateChain with certificate expiring soon`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(15, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertTrue(result.isValid)
        assertEquals(1, result.warnings.size)
        assertTrue(result.warnings.any { it.contains("Certificate expires in") })
        assertNotNull(result.daysUntilExpiry)
        assertTrue(result.daysUntilExpiry!! <= 30)
    }

    @Test
    fun `test validateCertificateChain with hostname mismatch`() {
        val certificate =
            createTestCertificate(
                subject = "CN=wrong.example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertFalse(result.isValid)
        assertEquals(1, result.issues.size)
        assertTrue(result.issues.any { it.contains("Hostname verification failed") })
        assertFalse(result.isHostnameValid)
    }

    @Test
    fun `test validateCertificateChain with weak certificate`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 1024,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertTrue(result.isValid)
        assertEquals(CertificateValidator.CertificateStrength.WEAK, result.certificateStrength)
    }

    @Test
    fun `test validateCertificateChain with strong certificate`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 4096,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertTrue(result.isValid)
        assertEquals(CertificateValidator.CertificateStrength.STRONG, result.certificateStrength)
    }

    @Test
    fun `test verifyHostname with exact match`() {
        val certificate =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "example.com")
        assertTrue(result)
    }

    @Test
    fun `test verifyHostname with case insensitive match`() {
        val certificate =
            createTestCertificate(
                subject = "CN=EXAMPLE.COM",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "example.com")
        assertTrue(result)
    }

    @Test
    fun `test verifyHostname with wildcard match`() {
        val certificate =
            createTestCertificate(
                subject = "CN=*.example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "sub.example.com")
        assertTrue(result)
    }

    @Test
    fun `test verifyHostname with wildcard no match`() {
        val certificate =
            createTestCertificate(
                subject = "CN=*.example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "other.com")
        assertFalse(result)
    }

    @Test
    fun `test verifyHostname with no match`() {
        val certificate =
            createTestCertificate(
                subject = "CN=wrong.example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "example.com")
        assertFalse(result)
    }

    @Test
    fun `test verifyHostname with invalid subject`() {
        val certificate =
            createTestCertificate(
                subject = "INVALID=SUBJECT",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val result = validator.verifyHostname(certificate, "example.com")
        assertFalse(result)
    }

    @Test
    fun `test certificate strength classification`() {
        val weakCert =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 1024,
            )

        val mediumCert =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val strongCert =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(30, ChronoUnit.DAYS),
                keySize = 4096,
            )

        val weakResult = validator.validateCertificateChain(listOf(weakCert), "example.com")
        val mediumResult = validator.validateCertificateChain(listOf(mediumCert), "example.com")
        val strongResult = validator.validateCertificateChain(listOf(strongCert), "example.com")

        assertEquals(CertificateValidator.CertificateStrength.WEAK, weakResult.certificateStrength)
        assertEquals(CertificateValidator.CertificateStrength.MEDIUM, mediumResult.certificateStrength)
        assertEquals(CertificateValidator.CertificateStrength.STRONG, strongResult.certificateStrength)
    }

    @Test
    fun `test certificate expiry edge cases`() {
        val expiringToday =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(1, ChronoUnit.HOURS),
                keySize = 2048,
            )

        val expiringTomorrow =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(25, ChronoUnit.HOURS),
                keySize = 2048,
            )

        val expiringNextMonth =
            createTestCertificate(
                subject = "CN=example.com",
                notAfter = Instant.now().plus(35, ChronoUnit.DAYS),
                keySize = 2048,
            )

        val todayResult = validator.validateCertificateChain(listOf(expiringToday), "example.com")
        val tomorrowResult = validator.validateCertificateChain(listOf(expiringTomorrow), "example.com")
        val nextMonthResult = validator.validateCertificateChain(listOf(expiringNextMonth), "example.com")

        assertTrue(todayResult.isValid)
        assertTrue(todayResult.warnings.isNotEmpty())

        assertTrue(tomorrowResult.isValid)
        assertTrue(tomorrowResult.warnings.isNotEmpty())

        assertTrue(nextMonthResult.isValid)
        assertTrue(nextMonthResult.warnings.isEmpty())
    }

    @Test
    fun `test multiple validation issues`() {
        val certificate =
            createTestCertificate(
                subject = "CN=wrong.example.com",
                notAfter = Instant.now().minus(1, ChronoUnit.DAYS),
                keySize = 1024,
            )

        val result = validator.validateCertificateChain(listOf(certificate), "example.com")

        assertFalse(result.isValid)
        assertEquals(2, result.issues.size)
        assertTrue(result.issues.any { it.contains("Certificate expired") })
        assertTrue(result.issues.any { it.contains("Hostname verification failed") })
        assertEquals(CertificateValidator.CertificateStrength.WEAK, result.certificateStrength)
    }

    private fun createTestCertificate(
        subject: String,
        notAfter: Instant,
        keySize: Int,
    ): X509Certificate {
        // Create a simple test certificate for testing purposes
        // In a real implementation, you would use a proper certificate factory
        // This is a simplified version for testing

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        val testKeyPair = keyPairGenerator.generateKeyPair()

        // Create a mock certificate that behaves like a real one
        return object : X509Certificate() {
            override fun getVersion(): Int = 3

            override fun getSerialNumber(): BigInteger = BigInteger.ONE

            override fun getIssuerDN(): java.security.Principal = X500Principal(subject)

            override fun getSubjectDN(): java.security.Principal = X500Principal(subject)

            override fun getNotBefore(): Date = Date.from(Instant.now().minus(1, ChronoUnit.DAYS))

            override fun getNotAfter(): Date = Date.from(notAfter)

            override fun getSignature(): ByteArray = ByteArray(0)

            override fun getSigAlgName(): String = "SHA256withRSA"

            override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"

            override fun getSigAlgParams(): ByteArray? = null

            override fun getIssuerUniqueID(): BooleanArray? = null

            override fun getSubjectUniqueID(): BooleanArray? = null

            override fun getTBSCertificate(): ByteArray = ByteArray(0)

            override fun getIssuerX500Principal(): X500Principal = X500Principal(subject)

            override fun getSubjectX500Principal(): X500Principal = X500Principal(subject)

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

            override fun checkValidity(date: Date) {}

            override fun getPublicKey(): java.security.PublicKey = testKeyPair.public

            override fun verify(key: java.security.PublicKey) {}

            override fun verify(
                key: java.security.PublicKey,
                sigProvider: String,
            ) {}

            override fun toString(): String = "TestCertificate($subject)"

            override fun getEncoded(): ByteArray = ByteArray(0)
        }
    }
}
