package org.example.formatter

import io.mockk.every
import io.mockk.mockk
import org.example.model.SSLConnection
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TextOutputFormatterTest {
    private val formatter = TextOutputFormatter()

    private fun stripAnsiCodes(text: String): String {
        return text.replace("""\u001B\[[;\d]*m""".toRegex(), "")
    }

    @Test
    fun `test format secure connection`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.serialNumber } returns BigInteger.valueOf(123456789)
        every { cert.encoded } returns "test".toByteArray()

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

        val output = stripAnsiCodes(formatter.format(connection))

        assertTrue(output.contains("SSL/TLS Connection Test Results"))
        assertTrue(output.contains("Basic Information"))
        assertTrue(output.contains("Host: example.com"))
        assertTrue(output.contains("Port: 443"))
        assertTrue(output.contains("Secure"))
        assertTrue(output.contains("Protocol Information"))
        assertTrue(output.contains("Protocol Version: TLSv1.3"))
        assertTrue(output.contains("Cipher Suite: TLS_AES_256_GCM_SHA384"))
        assertTrue(output.contains("Handshake Time: 100ms"))
        assertTrue(output.contains("Certificate Chain"))
        assertTrue(output.contains("Certificate 1"))
        assertTrue(output.contains("CN=example.com"))
        assertTrue(output.contains("CN=Test CA"))
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

        val output = stripAnsiCodes(formatter.format(connection))

        assertTrue(output.contains("SSL/TLS Connection Test Results"))
        assertTrue(output.contains("Basic Information"))
        assertTrue(output.contains("Host: example.com"))
        assertTrue(output.contains("Port: 443"))
        assertTrue(output.contains("Not Secure"))
        assertTrue(output.contains("Protocol Information"))
        assertTrue(output.contains("Protocol Version: Unknown (Connection failed)"))
        assertTrue(output.contains("Cipher Suite: Unknown"))
        assertTrue(output.contains("Handshake Time: 50ms"))
        assertTrue(output.contains("Certificate Chain: Empty"))
    }

    @Test
    fun `test format with certificate error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } throws RuntimeException("Certificate error")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } returns "test".toByteArray()

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

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("Error formatting certificate"))
    }

    @Test
    fun `test format with encoding error`() {
        val cert = mockk<X509Certificate>()
        every { cert.subjectX500Principal } returns X500Principal("CN=example.com")
        every { cert.issuerX500Principal } returns X500Principal("CN=Test CA")
        every { cert.notBefore } returns Date(System.currentTimeMillis() - 86400000)
        every { cert.notAfter } returns Date(System.currentTimeMillis() + 86400000)
        every { cert.encoded } throws RuntimeException("Encoding error")

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

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("Error formatting certificate"))
    }

    @Test
    fun `test getFileExtension`() {
        assertEquals("txt", formatter.getFileExtension())
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

        val output = stripAnsiCodes(formatter.format(connection))
        assertTrue(output.contains("test-host.example.com"))
    }
}
