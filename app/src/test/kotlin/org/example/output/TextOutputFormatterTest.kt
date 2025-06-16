package org.example.output

import io.mockk.every
import io.mockk.mockk
import org.example.domain.model.SSLConnection
import org.example.infrastructure.output.TextOutputFormatter
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import java.math.BigInteger
import java.time.Duration
import kotlin.system.measureTimeMillis

class TextOutputFormatterTest {
    private val formatter = TextOutputFormatter()

    private fun stripAnsiCodes(input: String): String {
        return input.replace("""\u001B\[[;\d]*m""".toRegex(), "")
    }

    @Test
    fun `test format successful connection`() {
        val time: Long = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            every { certificate.subjectX500Principal } returns X500Principal("CN=example.com")
            every { certificate.issuerX500Principal } returns X500Principal("CN=Let's Encrypt Authority X3")
            every { certificate.notBefore } returns Date(System.currentTimeMillis() - 86400000L)
            every { certificate.notAfter } returns Date(System.currentTimeMillis() + 86400000L * 90)
            every { certificate.serialNumber } returns BigInteger.valueOf(123456789)
            every { certificate.encoded } returns "test".toByteArray()
            every { certificate.keyUsage } returns null
            every { certificate.extendedKeyUsage } returns null

            val result = SSLConnection(
                host = "github.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(certificate)
            )

            val output = stripAnsiCodes(formatter.format(result))
            println("Actual output:")
            println(output)

            // Check header
            assertTrue(output.contains("SSL/TLS 连接测试结果"), "Missing header")
            
            // Check basic information
            assertTrue(output.contains("基本信息"), "Missing basic info section")
            assertTrue(output.contains("主机: github.com"), "Missing host info")
            assertTrue(output.contains("端口: 443"), "Missing port info")
            
            // Check connection status
            assertTrue(output.contains("✓ 安全"), "Missing security status")
            
            // Check protocol information
            assertTrue(output.contains("协议信息"), "Missing protocol info section")
            assertTrue(output.contains("协议版本: TLSv1.3"), "Missing protocol version")
            assertTrue(output.contains("加密套件: TLS_AES_256_GCM_SHA384"), "Missing cipher suite")
            assertTrue(output.contains("握手时间: 100ms"), "Missing handshake time")
            
            // Check certificate information
            assertTrue(output.contains("证书链"), "Missing certificate chain section")
            assertTrue(output.contains("证书 1"), "Missing certificate number")
            assertTrue(output.contains("类型: 服务器证书"), "Missing certificate type")
            assertTrue(output.contains("│ CN=example.com"), "Missing subject line")
            assertTrue(output.contains("│ CN=Let's Encrypt Authority X3"), "Missing issuer line")
            assertTrue(output.contains("有效期:"), "Missing validity period")
            assertTrue(output.contains("│   │ 指纹(SHA-256):"), "Missing fingerprint line")
            
            // Check footer
            assertTrue(output.contains("测试完成时间:"), "Missing completion time")
        }
        println("test format successful connection took ${time}ms")
    }

    @Test
    fun `test format failed connection with empty certificate chain`() {
        val time: Long = measureTimeMillis {
            val result = SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "Unknown",
                cipherSuite = "Unknown",
                handshakeTime = Duration.ofMillis(100),
                isSecure = false,
                certificateChain = emptyList()
            )

            val output = stripAnsiCodes(formatter.format(result))

            assertTrue(output.contains("主机: example.com"))
            assertTrue(output.contains("端口: 443"))
            assertTrue(output.contains("✗ 不安全"))
            assertTrue(output.contains("协议版本: Unknown"))
            assertTrue(output.contains("加密套件: Unknown"))
            assertTrue(output.contains("证书链: 空"))
            assertTrue(output.contains("握手时间: 100ms"))
        }
        println("test format failed connection with empty certificate chain took ${time}ms")
    }
} 