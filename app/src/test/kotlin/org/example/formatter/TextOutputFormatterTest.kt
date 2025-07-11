package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import java.time.Duration
import javax.security.auth.x500.X500Principal
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = CertificateValidator.ValidationResult(
                isValid = true,
                revocationStatus = CertificateValidator.RevocationStatus.Valid,
                errors = emptyList()
            ),
        )
        val result = formatter.format(connection)
        assertTrue(result.contains("example.com"))
        assertTrue(result.contains("443"))
        assertTrue(result.contains("TLSv1.3"))
        assertTrue(result.contains("TLS_AES_256_GCM_SHA384"))
        assertTrue(result.contains("Valid: true"))
        assertTrue(result.contains("Revocation Status: Valid"))
    }

    @Test
    fun testFormatWithRevokedCertificate() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = CertificateValidator.ValidationResult(
                isValid = false,
                revocationStatus = CertificateValidator.RevocationStatus.Revoked("OCSP: revoked"),
                errors = listOf("revoked by OCSP")
            ),
        )
        val result = formatter.format(connection)
        assertTrue(result.contains("Revocation Status: Revoked: OCSP: revoked"))
        assertTrue(result.contains("Errors:"))
        assertTrue(result.contains("revoked by OCSP"))
    }

    @Test
    fun testFormatWithUnknownRevocationStatus() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = CertificateValidator.ValidationResult(
                isValid = true,
                revocationStatus = CertificateValidator.RevocationStatus.Unknown,
                errors = emptyList()
            ),
        )
        val result = formatter.format(connection)
        assertTrue(result.contains("Revocation Status: Unknown"))
    }

    @Test
    fun testFormatWithErrorRevocationStatus() {
        val connection = createTestConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(mockCertificate),
            certificateValidation = CertificateValidator.ValidationResult(
                isValid = false,
                revocationStatus = CertificateValidator.RevocationStatus.Error("OCSP check failed"),
                errors = listOf("OCSP check failed")
            ),
        )
        val result = formatter.format(connection)
        assertTrue(result.contains("Revocation Status: Error: OCSP check failed"))
        assertTrue(result.contains("Errors:"))
        assertTrue(result.contains("OCSP check failed"))
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
            override fun getSerialNumber() = java.math.BigInteger.ONE
            override fun getIssuerDN() = X500Principal(subject)
            override fun getSubjectDN() = X500Principal(subject)
            override fun getNotBefore() = java.util.Date()
            override fun getNotAfter() = java.util.Date()
            override fun getSignature() = ByteArray(0)
            override fun getSigAlgName() = "SHA256withRSA"
            override fun getSigAlgOID() = "1.2.840.113549.1.1.11"
            override fun getSigAlgParams(): ByteArray? = null
            override fun getIssuerUniqueID(): BooleanArray? = null
            override fun getSubjectUniqueID(): BooleanArray? = null
            override fun getTBSCertificate() = ByteArray(0)
            override fun getIssuerX500Principal() = X500Principal(subject)
            override fun getSubjectX500Principal() = X500Principal(subject)
            override fun getKeyUsage(): BooleanArray? = null
            override fun getExtendedKeyUsage(): List<String>? = null
            override fun getBasicConstraints() = -1
            override fun getSubjectAlternativeNames(): Collection<List<*>>? = null
            override fun getIssuerAlternativeNames(): Collection<List<*>>? = null
            override fun getCriticalExtensionOIDs(): Set<String>? = null
            override fun getExtensionValue(oid: String): ByteArray? = null
            override fun getNonCriticalExtensionOIDs(): Set<String>? = null
            override fun hasUnsupportedCriticalExtension() = false
            override fun checkValidity() {}
            override fun checkValidity(date: java.util.Date) {}
            override fun getPublicKey() = object : java.security.PublicKey {
                override fun getAlgorithm() = "RSA"
                override fun getFormat() = "X.509"
                override fun getEncoded() = ByteArray(0)
            }
            override fun verify(key: java.security.PublicKey) {}
            override fun verify(key: java.security.PublicKey, sigProvider: String) {}
            override fun toString() = "MockCertificate"
            override fun getEncoded() = ByteArray(0)
        }
    }
}
