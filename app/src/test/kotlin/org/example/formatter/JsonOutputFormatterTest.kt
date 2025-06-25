package org.example.formatter

import io.mockk.every
import io.mockk.mockk
import org.example.model.SSLConnection
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonOutputFormatterTest {
    private val formatter = JsonOutputFormatter()

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
        // 检查基本的JSON结构
        assertTrue(result.startsWith("{"))
        assertTrue(result.endsWith("}"))
        assertTrue(result.contains("\"host\" :"))
        assertTrue(result.contains("\"port\" :"))
        assertTrue(result.contains("\"isSecure\" :"))
        assertTrue(result.contains("\"protocol\" :"))
        assertTrue(result.contains("\"cipherSuite\" :"))
        assertTrue(result.contains("\"certificates\" :"))
        // 检查证书信息字段
        assertTrue(result.contains("\"subject\" : \"CN=example.com\""))
        assertTrue(result.contains("\"issuer\" : \"CN=DigiCert Inc\""))
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
        assertTrue(result.contains("\"isSecure\" : false"))
        assertTrue(result.contains("\"protocol\" : \"HTTP\""))
        assertTrue(result.contains("\"cipherSuite\" : \"\""))
        assertTrue(result.contains("\"certificates\" :"))
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
        // 检查包含certificates字段和空数组
        assertTrue(result.contains("\"certificates\""))
        assertTrue(result.contains("[]") || result.contains("[ ]"))
    }

    @Test
    fun `test JSON structure validation`() {
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
        assertTrue(result.startsWith("{"))
        assertTrue(result.endsWith("}"))
        assertTrue(result.contains("\"host\" :"))
        assertTrue(result.contains("\"port\" :"))
        assertTrue(result.contains("\"isSecure\" :"))
        assertTrue(result.contains("\"protocol\" :"))
        assertTrue(result.contains("\"cipherSuite\" :"))
        assertTrue(result.contains("\"certificates\" :"))
        // 验证证书链结构，检查证书信息字段
        assertTrue(result.contains("\"subject\" : \"CN=test.com, O=Test Org\""))
        assertTrue(result.contains("\"subject\" : \"CN=Test CA, O=Test Org\""))
        assertTrue(result.contains("\"issuer\" : \"CN=Root CA, O=Root Org\""))
    }

    @Test
    fun `test format secure connection`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } returns "test".toByteArray()
        every { cert.serialNumber } returns java.math.BigInteger.valueOf(12345)

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

        val output = formatter.format(connection)

        assertTrue(output.contains("\"host\" : \"example.com\""))
        assertTrue(output.contains("\"port\" : 443"))
        assertTrue(output.contains("\"protocol\" : \"TLSv1.3\""))
        assertTrue(output.contains("\"cipherSuite\" : \"TLS_AES_256_GCM_SHA384\""))
        assertTrue(output.contains("\"handshakeTimeMs\" : 100"))
        assertTrue(output.contains("\"isSecure\" : true"))
        assertTrue(output.contains("\"certificates\""))
        assertTrue(output.contains("\"subject\" : \"CN=example.com\""))
        assertTrue(output.contains("\"issuer\" : \"CN=Test CA\""))
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

        val output = formatter.format(connection)

        assertTrue(output.contains("\"host\" : \"example.com\""))
        assertTrue(output.contains("\"port\" : 443"))
        assertTrue(output.contains("\"protocol\" : \"Unknown (Connection failed)\""))
        assertTrue(output.contains("\"cipherSuite\" : \"Unknown\""))
        assertTrue(output.contains("\"handshakeTimeMs\" : 50"))
        assertTrue(output.contains("\"isSecure\" : false"))
        assertTrue(output.contains("\"certificates\" : [ ]"))
    }

    @Test
    fun `test format with multiple certificates`() {
        val cert1 = mockk<X509Certificate>()
        val cert2 = mockk<X509Certificate>()

        every { cert1.subjectX500Principal } returns X500Principal("CN=leaf.example.com")
        every { cert1.issuerX500Principal } returns X500Principal("CN=intermediate.ca")
        every { cert1.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert1.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert1.encoded } returns "test1".toByteArray()
        every { cert1.serialNumber } returns java.math.BigInteger.valueOf(12345)

        every { cert2.subjectX500Principal } returns X500Principal("CN=intermediate.ca")
        every { cert2.issuerX500Principal } returns X500Principal("CN=root.ca")
        every { cert2.notBefore } returns Date(System.currentTimeMillis() - 172800000)
        every { cert2.notAfter } returns Date(System.currentTimeMillis() + 172800000)
        every { cert2.encoded } returns "test2".toByteArray()
        every { cert2.serialNumber } returns java.math.BigInteger.valueOf(67890)

        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(cert1, cert2),
            )

        val output = formatter.format(connection)

        assertTrue(output.contains("\"certificates\""))
        assertTrue(output.contains("\"subject\" : \"CN=leaf.example.com\""))
        assertTrue(output.contains("\"subject\" : \"CN=intermediate.ca\""))
        assertTrue(output.contains("\"issuer\" : \"CN=root.ca\""))
    }

    @Test
    fun `test format with certificate error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } throws RuntimeException("Certificate error")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } returns "test".toByteArray()
        every { cert.serialNumber } returns java.math.BigInteger.valueOf(12345)

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

        val output = formatter.format(connection)
        // Should handle the error gracefully and still produce valid JSON
        assertTrue(output.contains("\"certificates\""))
    }

    @Test
    fun `test format with encoding error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } throws RuntimeException("Encoding error")
        every { cert.serialNumber } returns java.math.BigInteger.valueOf(12345)

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

        val output = formatter.format(connection)
        // Should handle the error gracefully and still produce valid JSON
        assertTrue(output.contains("\"certificates\""))
    }

    @Test
    fun `test getFileExtension`() {
        assertEquals("json", formatter.getFileExtension())
    }

    @Test
    fun `test format with very long hostname`() {
        val longHost = "a".repeat(100) + ".example.com"
        val connection =
            SSLConnection(
                host = longHost,
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(150),
                isSecure = true,
                certificateChain = emptyList(),
            )

        val result = formatter.format(connection)

        assertTrue(result.contains(longHost))
        assertTrue(result.contains("443"))
        assertTrue(result.contains("TLSv1.3"))
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

        val output = formatter.format(connection)
        assertTrue(output.contains("\"host\" : \"test-host.example.com\""))
    }

    @Test
    fun `test format with zero handshake time`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(0),
                isSecure = true,
                certificateChain = emptyList(),
            )

        val output = formatter.format(connection)
        assertTrue(output.contains("\"handshakeTimeMs\" : 0"))
    }

    @Test
    fun `test format with very long handshake time`() {
        val connection =
            SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(999999),
                isSecure = true,
                certificateChain = emptyList(),
            )

        val output = formatter.format(connection)
        assertTrue(output.contains("\"handshakeTimeMs\" : 999999"))
    }
}
