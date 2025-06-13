package org.example.output

import org.example.model.SSLTestResult
import org.example.model.ValidationResult
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.security.cert.X509Certificate
import org.mockito.Mockito
import org.mockito.Mockito.`when`

class ResultFormatterImplTest {
    private fun sampleResult(): SSLTestResult {
        val cert = Mockito.mock(X509Certificate::class.java)
        `when`(cert.subjectX500Principal).thenReturn(javax.security.auth.x500.X500Principal("CN=example.com"))
        `when`(cert.issuerX500Principal).thenReturn(javax.security.auth.x500.X500Principal("CN=issuer.com"))
        `when`(cert.notAfter).thenReturn(java.util.Date())
        val validation = ValidationResult(true, true, true, true, "ok")
        return SSLTestResult(
            hostname = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            certificateChain = listOf(cert),
            validationResult = validation
        )
    }

    @Test
    fun `formatAsText returns human readable string`() {
        val formatter = ResultFormatterImpl()
        val text = formatter.formatAsText(listOf(sampleResult()))
        assertTrue(text.contains("SSL Test Result for example.com:443"))
        assertTrue(text.contains("TLS_AES_128_GCM_SHA256"))
    }

    @Test
    fun `json and yaml formatting include hostname`() {
        val formatter = ResultFormatterImpl()
        val results = listOf(sampleResult())
        val json = formatter.formatAsJson(results)
        val yaml = formatter.formatAsYaml(results)
        assertTrue(json.contains("example.com"))
        assertTrue(yaml.contains("example.com"))
    }

    @Test
    fun `formatAsText handles empty list`() {
        val formatter = ResultFormatterImpl()
        assertEquals("No SSL test results to display.", formatter.formatAsText(emptyList()))
    }
}
