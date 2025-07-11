package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import java.time.Duration
import javax.security.auth.x500.X500Principal
import kotlin.test.assertTrue

class YamlOutputFormatterTest {
    private lateinit var formatter: YamlOutputFormatter
    private lateinit var mockCertificate: X509Certificate

    @BeforeEach
    fun setUp() {
        formatter = YamlOutputFormatter()
        mockCertificate = createMockCertificate("CN=example.com")
    }

    @Test
    fun `test format with valid SSL connection`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(123),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation =
                    CertificateValidator.ValidationResult(
                        isValid = true,
                        revocationStatus = CertificateValidator.RevocationStatus.Valid,
                        errors = emptyList(),
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("certificateValidation:"))
        assertTrue(result.contains("isValid: true"))
        assertTrue(result.contains("revocationStatus: \"Valid\""))
        assertTrue(result.contains("errors: []"))
    }

    @Test
    fun `test format with revoked certificate`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(123),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation =
                    CertificateValidator.ValidationResult(
                        isValid = false,
                        revocationStatus = CertificateValidator.RevocationStatus.Revoked("OCSP: revoked"),
                        errors = listOf("revoked by OCSP"),
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("certificateValidation:"))
        assertTrue(result.contains("revocationStatus: \"Revoked: OCSP: revoked\""))
        assertTrue(result.contains("errors:"))
        assertTrue(result.contains("- \"revoked by OCSP\""))
    }

    @Test
    fun `test format with unknown revocation status`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(123),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation =
                    CertificateValidator.ValidationResult(
                        isValid = true,
                        revocationStatus = CertificateValidator.RevocationStatus.Unknown,
                        errors = emptyList(),
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("certificateValidation:"))
        assertTrue(result.contains("revocationStatus: \"Unknown\""))
        assertTrue(result.contains("errors: []"))
    }

    @Test
    fun `test format with error revocation status`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(123),
                isSecure = true,
                certificateChain = listOf(mockCertificate),
                certificateValidation =
                    CertificateValidator.ValidationResult(
                        isValid = false,
                        revocationStatus = CertificateValidator.RevocationStatus.Error("OCSP check failed"),
                        errors = listOf("OCSP check failed"),
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("certificateValidation:"))
        assertTrue(result.contains("revocationStatus: \"Error: OCSP check failed\""))
        assertTrue(result.contains("errors:"))
        assertTrue(result.contains("- \"OCSP check failed\""))
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

            override fun getPublicKey() =
                object : java.security.PublicKey {
                    override fun getAlgorithm() = "RSA"

                    override fun getFormat() = "X.509"

                    override fun getEncoded() = ByteArray(0)
                }

            override fun verify(key: java.security.PublicKey) {}

            override fun verify(
                key: java.security.PublicKey,
                sigProvider: String,
            ) {}

            override fun toString() = "MockCertificate"

            override fun getEncoded() = ByteArray(0)
        }
    }
}
