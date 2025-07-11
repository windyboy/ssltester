package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * EmojiTextOutputFormatter 测试类。
 */
class EmojiTextOutputFormatterTest {
//    @Test
//    fun `test format with valid connection`() {
//        val formatter = EmojiTextOutputFormatter()
//        val connection = createMockSSLConnection()
//
//        val cert = connection.certificateChain.first()
//        println("subjectX500Principal.getName(RFC2253): " + cert.subjectX500Principal.getName("RFC2253"))
//        println("issuerX500Principal.getName(RFC2253): " + cert.issuerX500Principal.getName("RFC2253"))
//
//        val result = formatter.format(connection)
//
//        // 调试：打印实际输出
//        println("=== ACTUAL OUTPUT ===")
//        println(result)
//        println("=== END OUTPUT ===")
//
//        assert(result.isNotEmpty())
//        assert(result.contains("🔒 SSL证书信息"))
//        assert(result.contains("📋 主题"))
//        assert(result.contains("🏢 颁发者"))
//        assert(result.contains("📅 有效期"))
//        assert(result.contains("✅ 状态"))
//        assert(result.contains("🔗 证书链信息"))
//        assert(result.contains("📊 详细信息"))
//    }

    @Test
    fun `test format with empty certificate chain`() {
        val formatter = EmojiTextOutputFormatter()
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = emptyList(),
                certificateValidation = null,
            )

        val result = formatter.format(connection)

        assert(result.isNotEmpty())
        assert(result.contains("🔒 SSL证书信息"))
        assert(!result.contains("📋 主题")) // 没有证书时不应该显示主题信息
    }

    @Test
    fun `test getFileExtension`() {
        val formatter = EmojiTextOutputFormatter()
        assert(formatter.getFileExtension() == "txt")
    }

    @Test
    fun `test format with exception handling`() {
        val formatter = EmojiTextOutputFormatter()
        // 创建一个会导致异常的连接对象
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(createMockCertificate()),
                certificateValidation = null,
            )

        assertDoesNotThrow {
            formatter.format(connection)
        }
    }

    private fun createMockSSLConnection(): SSLConnection {
        return SSLConnection(
            host = "github.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(150),
            isSecure = true,
            certificateChain = listOf(createMockCertificate()),
            certificateValidation = createMockValidationResult(),
        )
    }

    private fun createMockCertificate(): X509Certificate {
        return object : X509Certificate() {
            override fun getVersion(): Int = 3

            override fun getSerialNumber(): java.math.BigInteger = java.math.BigInteger("123456789")

            override fun getIssuerDN(): java.security.Principal = X500Principal("CN=Sectigo Limited,O=Sectigo Limited,C=US")

            override fun getSubjectDN(): java.security.Principal =
                X500Principal(
                    "CN=github.com,O=GitHub, Inc.,L=San Francisco,ST=California,C=US",
                )

            override fun getSubjectX500Principal(): X500Principal =
                X500Principal(
                    "CN=github.com,O=GitHub, Inc.,L=San Francisco,ST=California,C=US",
                )

            override fun getIssuerX500Principal(): X500Principal = X500Principal("CN=Sectigo Limited,O=Sectigo Limited,C=US")

            override fun getNotBefore(): Date = Date.from(LocalDateTime.now().minusDays(100).atZone(ZoneId.systemDefault()).toInstant())

            override fun getNotAfter(): Date = Date.from(LocalDateTime.now().plusDays(200).atZone(ZoneId.systemDefault()).toInstant())

            override fun getTBSCertificate(): ByteArray = ByteArray(0)

            override fun getSignature(): ByteArray = ByteArray(0)

            override fun getSigAlgName(): String = "SHA256withECDSA"

            override fun getSigAlgOID(): String = "1.2.840.10045.4.3.2"

            override fun getSigAlgParams(): ByteArray = ByteArray(0)

            override fun getIssuerUniqueID(): BooleanArray = BooleanArray(0)

            override fun getSubjectUniqueID(): BooleanArray = BooleanArray(0)

            override fun getKeyUsage(): BooleanArray = BooleanArray(9) { false }

            override fun getExtendedKeyUsage(): List<String> = emptyList()

            override fun getBasicConstraints(): Int = -1

            override fun getSubjectAlternativeNames(): Collection<List<*>> = listOf(listOf(2, "github.com"), listOf(2, "www.github.com"))

            override fun getIssuerAlternativeNames(): Collection<List<*>> = emptyList()

            override fun getEncoded(): ByteArray = ByteArray(0)

            override fun verify(key: java.security.PublicKey) {}

            override fun verify(
                key: java.security.PublicKey,
                sigProvider: String,
            ) {}

            override fun getPublicKey(): java.security.PublicKey =
                object : java.security.PublicKey {
                    override fun getAlgorithm(): String = "EC"

                    override fun getFormat(): String = "X.509"

                    override fun getEncoded(): ByteArray = ByteArray(32) { 1 }
                }

            override fun checkValidity() {}

            override fun checkValidity(date: Date) {}

            override fun toString(): String = "Mock Certificate"

            override fun hasUnsupportedCriticalExtension(): Boolean = false

            override fun getCriticalExtensionOIDs(): Set<String>? = null

            override fun getNonCriticalExtensionOIDs(): Set<String>? = null

            override fun getExtensionValue(oid: String?): ByteArray? = null
        }
    }

    private fun createMockValidationResult(): CertificateValidator.ValidationResult {
        return CertificateValidator.ValidationResult(
            isValid = true,
            issues = emptyList(),
            warnings = emptyList(),
            daysUntilExpiry = 200,
            isHostnameValid = true,
            certificateStrength = CertificateValidator.CertificateStrength.STRONG,
        )
    }
}
