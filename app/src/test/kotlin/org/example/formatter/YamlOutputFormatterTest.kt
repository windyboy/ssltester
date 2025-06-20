package org.example.formatter

import io.mockk.every
import io.mockk.mockk
import org.example.model.SSLConnection
import java.security.cert.X509Certificate
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertTrue

class YamlOutputFormatterTest {
    private val formatter = YamlOutputFormatter()

    private fun mockCert(
        subject: String,
        issuer: String,
    ): X509Certificate {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal.toString() } returns subject
        every { cert.issuerX500Principal.toString() } returns issuer
        every { cert.notBefore.toInstant() } returns java.time.Instant.parse("2023-01-01T00:00:00Z")
        every { cert.notAfter.toInstant() } returns java.time.Instant.parse("2024-01-01T23:59:59Z")
        every { cert.serialNumber } returns java.math.BigInteger("1234567890")
        return cert
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
                certificateChain =
                    listOf(
                        mockCert("CN=example.com", "CN=DigiCert Inc"),
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("host: \"example.com\""))
        assertTrue(result.contains("port: 443"))
        assertTrue(result.contains("isSecure: true"))
        assertTrue(result.contains("protocol: \"TLSv1.3\""))
        assertTrue(result.contains("cipherSuite: \"TLS_AES_256_GCM_SHA384\""))
        assertTrue(result.contains("handshakeTimeMs: 123"))
        assertTrue(result.contains("certificates:"))
        // 检查证书信息的具体字段
        assertTrue(result.contains("subject: \"CN=example.com\""))
        assertTrue(result.contains("issuer: \"CN=DigiCert Inc\""))
    }

    @Test
    fun `test format with insecure connection`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 80,
                protocol = "HTTP",
                cipherSuite = "",
                handshakeTime = Duration.ZERO,
                isSecure = false,
                certificateChain = emptyList(),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("isSecure: false"))
        assertTrue(result.contains("protocol: \"HTTP\""))
        assertTrue(result.contains("cipherSuite: \"\""))
        assertTrue(result.contains("certificates:"))
        assertTrue(result.contains("[]") || result.contains("[ ]"))
    }

    @Test
    fun `test format with empty certificate chain`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.2",
                cipherSuite = "TLS_RSA_WITH_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(50),
                isSecure = true,
                certificateChain = emptyList(),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("certificates:"))
        assertTrue(result.contains("[]") || result.contains("[ ]"))
    }

    @Test
    fun `test YAML structure validation`() {
        val cert1 =
            mockCert(
                "CN=test.com, O=Test Org",
                "CN=Test CA, O=Test Org",
            )
        val cert2 =
            mockCert(
                "CN=Test CA, O=Test Org",
                "CN=Root CA, O=Root Org",
            )
        val connection =
            SSLConnection(
                host = "test.com",
                port = 8443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_CHACHA20_POLY1305_SHA256",
                handshakeTime = Duration.ofMillis(200),
                isSecure = true,
                certificateChain =
                    listOf(
                        cert1,
                        cert2,
                    ),
            )
        val result = formatter.format(connection)
        assertTrue(result.contains("host: \"test.com\""))
        assertTrue(result.contains("port: 8443"))
        assertTrue(result.contains("isSecure: true"))
        assertTrue(result.contains("protocol: \"TLSv1.3\""))
        assertTrue(result.contains("cipherSuite: \"TLS_CHACHA20_POLY1305_SHA256\""))
        assertTrue(result.contains("certificates:"))
        // 验证证书链结构，检查证书信息的具体字段
        assertTrue(result.contains("subject: \"CN=test.com, O=Test Org\""))
        assertTrue(result.contains("subject: \"CN=Test CA, O=Test Org\""))
        assertTrue(result.contains("issuer: \"CN=Root CA, O=Root Org\""))
    }

    @Test
    fun `test YAML indentation and formatting`() {
        val connection =
            SSLConnection(
                host = "simple.com",
                port = 443,
                protocol = "TLSv1.2",
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                handshakeTime = Duration.ofMillis(10),
                isSecure = true,
                certificateChain =
                    listOf(
                        mockCert("CN=simple.com", "CN=Simple CA"),
                    ),
            )
        val result = formatter.format(connection)
        val lines = result.lines()
        assertTrue(lines.any { it.startsWith("host:") })
        assertTrue(lines.any { it.startsWith("certificates:") })
        assertTrue(lines.any { it.trim().startsWith("- subject:") })
        assertTrue(lines.any { it.trim().startsWith("issuer:") })
    }
}
