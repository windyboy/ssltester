package org.example

import kotlinx.coroutines.runBlocking
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
    fun `test validateCertificateChain with empty certificates`() =
        runBlocking {
            val result = validator.validateCertificateChain(emptyList())
            assertFalse(result.isValid)
            assertEquals(1, result.errors.size)
            assertTrue(result.errors.contains("No certificates provided"))
            assertTrue(result.revocationStatus is CertificateValidator.RevocationStatus.Error)
        }

    @Test
    fun `test validateCertificateChain with single certificate`() =
        runBlocking {
            val certificate =
                createTestCertificate(
                    "CN=example.com",
                    Instant.now().plus(30, ChronoUnit.DAYS),
                    2048,
                )
            val result = validator.validateCertificateChain(listOf(certificate))
            // 单证书链会直接返回 Unknown
            assertTrue(result.isValid)
            assertTrue(result.revocationStatus is CertificateValidator.RevocationStatus.Unknown)
            assertTrue(result.errors.any { it.contains("too short", ignoreCase = true) })
        }

    @Test
    fun `test validateCertificateChain with expired certificate`() =
        runBlocking {
            val certificate =
                createTestCertificate(
                    "CN=example.com",
                    Instant.now().minus(1, ChronoUnit.DAYS),
                    2048,
                )
            val result = validator.validateCertificateChain(listOf(certificate))
            // 依然是单证书链，返回 Unknown
            assertTrue(result.isValid)
            assertTrue(result.revocationStatus is CertificateValidator.RevocationStatus.Unknown)
        }

    private fun createTestCertificate(
        subject: String,
        notAfter: Instant,
        keySize: Int,
    ): X509Certificate {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        val testKeyPair = keyPairGenerator.generateKeyPair()
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
