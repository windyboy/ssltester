package org.example.output

import kotlin.test.*
import java.security.cert.X509Certificate
import java.util.*
import org.example.config.SSLTestConfig

class ResultFormatterTest {
    private lateinit var formatter: ResultFormatter
    private lateinit var config: SSLTestConfig

    @BeforeTest
    fun setUp() {
        config = SSLTestConfig().apply {
            url = "https://example.com"
            format = SSLTestConfig.OutputFormat.TEXT
            verbose = false
            outputFile = null
        }
        formatter = ResultFormatter(config)
    }

    @Test
    fun `test format success result`() {
        val result = mapOf(
            "status" to "success",
            "httpStatus" to 200,
            "cipherSuite" to "ECDHE-RSA-AES256-GCM-SHA384",
            "hostnameVerified" to true
        )
        
        formatter.formatAndOutput(result)
    }

    @Test
    fun `test format error result`() {
        val result = mapOf(
            "status" to "error",
            "error" to "Connection refused",
            "errorCause" to "Connection timeout"
        )
        
        formatter.formatAndOutput(result)
    }

    @Test
    fun `test format certificate info`() {
        val certInfo = mapOf(
            "subjectDN" to "CN=example.com",
            "issuerDN" to "CN=Let's Encrypt Authority X3",
            "version" to 3,
            "serialNumber" to "1234567890",
            "validFrom" to Date(),
            "validUntil" to Date(),
            "signatureAlgorithm" to "SHA256withRSA",
            "publicKeyAlgorithm" to "RSA",
            "subjectAlternativeNames" to mapOf(
                "DNS" to "example.com",
                "IP" to "192.168.1.1"
            )
        )
        
        formatter.formatAndOutput(certInfo)
    }

    @Test
    fun `test format certificate chain`() {
        val result = mapOf(
            "certificateChain" to listOf(
                mapOf(
                    "subjectDN" to "CN=example.com",
                    "issuerDN" to "CN=Let's Encrypt Authority X3",
                    "version" to 3,
                    "serialNumber" to "1234567890",
                    "validFrom" to Date(),
                    "validUntil" to Date(),
                    "signatureAlgorithm" to "SHA256withRSA",
                    "publicKeyAlgorithm" to "RSA"
                )
            )
        )
        
        formatter.formatAndOutput(result)
    }

    @Test
    fun `test format empty result`() {
        val result = mapOf(
            "status" to "success",
            "httpStatus" to 200
        )
        
        formatter.formatAndOutput(result)
    }

    @Test
    fun `test format with special characters`() {
        val result = mapOf(
            "status" to "success",
            "httpStatus" to 200,
            "cipherSuite" to "ECDHE-RSA-AES256-GCM-SHA384",
            "hostnameVerified" to true
        )
        
        formatter.formatAndOutput(result)
    }
} 