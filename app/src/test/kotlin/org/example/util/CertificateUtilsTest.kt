package org.example.util

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import java.math.BigInteger
import java.text.SimpleDateFormat
import kotlin.system.measureTimeMillis

class CertificateUtilsTest {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    @Test
    fun `test get certificate subject`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val subject = X500Principal("CN=example.com, O=Example Organization, C=US")
            every { certificate.subjectX500Principal } returns subject

            val result = CertificateUtils.getCertificateSubject(certificate)

            assertEquals("CN=example.com, O=Example Organization, C=US", result)
        }
        println("test get certificate subject took ${time}ms")
    }

    @Test
    fun `test get certificate issuer`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val issuer = X500Principal("CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US")
            every { certificate.issuerX500Principal } returns issuer

            val result = CertificateUtils.getCertificateIssuer(certificate)

            assertEquals("CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US", result)
        }
        println("test get certificate issuer took ${time}ms")
    }

    @Test
    fun `test get certificate validity period`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val notBefore = Date(System.currentTimeMillis() - 86400000) // 1天前
            val notAfter = Date(System.currentTimeMillis() + 86400000 * 90) // 90天后
            every { certificate.notBefore } returns notBefore
            every { certificate.notAfter } returns notAfter

            val result = CertificateUtils.getCertificateValidityPeriod(certificate)

            assertTrue(result.contains("Not Before: ${dateFormat.format(notBefore)}"))
            assertTrue(result.contains("Not After: ${dateFormat.format(notAfter)}"))
        }
        println("test get certificate validity period took ${time}ms")
    }

    @Test
    fun `test get certificate serial number`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val serialNumber = BigInteger.valueOf(123456789)
            every { certificate.serialNumber } returns serialNumber

            val result = CertificateUtils.getCertificateSerialNumber(certificate)

            assertEquals("75BCD15", result) // 123456789 in hex
        }
        println("test get certificate serial number took ${time}ms")
    }

    @Test
    fun `test get certificate serial number with zero`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val serialNumber = BigInteger.ZERO
            every { certificate.serialNumber } returns serialNumber

            val result = CertificateUtils.getCertificateSerialNumber(certificate)

            assertEquals("0", result)
        }
        println("test get certificate serial number with zero took ${time}ms")
    }

    @Test
    fun `test get certificate serial number with large number`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val serialNumber = BigInteger("FFFFFFFFFFFFFFFF", 16) // 最大16位十六进制数
            every { certificate.serialNumber } returns serialNumber

            val result = CertificateUtils.getCertificateSerialNumber(certificate)

            assertEquals("FFFFFFFFFFFFFFFF", result)
        }
        println("test get certificate serial number with large number took ${time}ms")
    }

    @Test
    fun `test get certificate validity period with same dates`() {
        val time = measureTimeMillis {
            val certificate = mockk<X509Certificate>()
            val date = Date()
            every { certificate.notBefore } returns date
            every { certificate.notAfter } returns date

            val result = CertificateUtils.getCertificateValidityPeriod(certificate)

            val formattedDate = dateFormat.format(date)
            assertTrue(result.contains("Not Before: $formattedDate"))
            assertTrue(result.contains("Not After: $formattedDate"))
        }
        println("test get certificate validity period with same dates took ${time}ms")
    }

    @Test
    fun `test get certificate subject with special characters`() {
        val certificate = mockk<X509Certificate>()
        val subject = X500Principal("CN=example.com, O=Example & Company, C=US")
        every { certificate.subjectX500Principal } returns subject

        val result = CertificateUtils.getCertificateSubject(certificate)

        assertEquals("CN=example.com, O=Example & Company, C=US", result)
    }
} 