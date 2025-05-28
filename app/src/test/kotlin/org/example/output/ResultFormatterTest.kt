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
    fun `should format successful connection result`() {
        // Given
        val result = mapOf(
            "status" to "success",
            "httpStatus" to 200,
            "cipherSuite" to "ECDHE-RSA-AES256-GCM-SHA384",
            "hostnameVerified" to true
        )
        
        // When
        val output = formatter.formatAndOutput(result)
        
        // Then
        assertTrue(output.contains("Status: success"))
        assertTrue(output.contains("HTTP Status: 200"))
        assertTrue(output.contains("Cipher Suite: ECDHE-RSA-AES256-GCM-SHA384"))
    }

    @Test
    fun `should format connection error result`() {
        // Given
        val result = mapOf(
            "status" to "error",
            "error" to "Connection refused",
            "errorCause" to "Connection timeout"
        )
        
        // When
        val output = formatter.formatAndOutput(result)
        
        // Then
        assertTrue(output.contains("Status: error"))
        assertTrue(output.contains("Error: Connection refused"))
        assertTrue(output.contains("Cause: Connection timeout"))
    }

    @Test
    fun `should format certificate information`() {
        // Given
        val certInfo = mapOf(
            "subjectDN" to "CN=example.com",
            "issuerDN" to "CN=Let's Encrypt Authority X3",
            "validFrom" to Date(),
            "validUntil" to Date(),
            "signatureAlgorithm" to "SHA256withRSA"
        )
        
        // When
        val output = formatter.formatAndOutput(certInfo)
        
        // Then
        assertTrue(output.contains("Subject: CN=example.com"))
        assertTrue(output.contains("Issuer: CN=Let's Encrypt Authority X3"))
        assertTrue(output.contains("Signature Algorithm: SHA256withRSA"))
    }

    @Test
    fun `should format empty result with minimal information`() {
        // Given
        val result = mapOf(
            "status" to "success",
            "httpStatus" to 200
        )
        
        // When
        val output = formatter.formatAndOutput(result)
        
        // Then
        assertTrue(output.contains("Status: success"))
        assertTrue(output.contains("HTTP Status: 200"))
        assertFalse(output.contains("Cipher Suite:"))
    }
} 