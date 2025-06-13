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

    @Test
    fun `test format successful connection`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            every { certificate.subjectX500Principal } returns X500Principal("CN=example.com")
            every { certificate.issuerX500Principal } returns X500Principal("CN=Let's Encrypt Authority X3")
            every { certificate.notBefore } returns Date(System.currentTimeMillis() - 86400000)
            every { certificate.notAfter } returns Date(System.currentTimeMillis() + 86400000 * 90)
            every { certificate.serialNumber } returns BigInteger.valueOf(123456789)

            val result = SSLConnection(
                host = "github.com",
                port = 443,
                protocol = "TLSv1.3",
                cipherSuite = "TLS_AES_256_GCM_SHA384",
                handshakeTime = Duration.ofMillis(100),
                isSecure = true,
                certificateChain = listOf(certificate)
            )

            val output = formatter.format(result)

            assertTrue(output.contains("Status: Success"))
            assertTrue(output.contains("Protocol: TLSv1.3"))
            assertTrue(output.contains("Cipher Suite: TLS_AES_256_GCM_SHA384"))
            assertTrue(output.contains("Subject: CN=example.com"))
            assertTrue(output.contains("Issuer: CN=Let's Encrypt Authority X3"))
            assertTrue(output.contains("Valid Until:"))
        }
        println("test format successful connection took ${time}ms")
    }

    @Test
    fun `test format failed connection with empty certificate chain`() {
        val time = measureTimeMillis {
            val result = SSLConnection(
                host = "example.com",
                port = 443,
                protocol = "",
                cipherSuite = "",
                handshakeTime = Duration.ofMillis(100),
                isSecure = false,
                certificateChain = emptyList()
            )

            val output = formatter.format(result)

            assertTrue(output.contains("Host: example.com"))
            assertTrue(output.contains("Port: 443"))
            assertTrue(output.contains("Status: Failed"))
            assertTrue(output.contains("Protocol: N/A"))
            assertTrue(output.contains("Cipher Suite: N/A"))
            assertTrue(output.contains("Certificate Chain: Empty"))
            assertTrue(output.contains("Handshake Time: 100ms"))
        }
        println("test format failed connection with empty certificate chain took ${time}ms")
    }
} 