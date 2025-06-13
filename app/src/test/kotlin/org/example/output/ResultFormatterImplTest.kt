package org.example.output

import org.example.model.SSLTestResult
import org.example.model.ValidationResult
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class ResultFormatterImplTest {
    private fun loadCert(path: String): X509Certificate {
        val stream = this::class.java.classLoader.getResourceAsStream(path) ?: throw IllegalArgumentException("Missing cert $path")
        return CertificateFactory.getInstance("X.509").generateCertificate(stream) as X509Certificate
    }

    private fun sampleResult(): SSLTestResult {
        val cert = loadCert("certs/leaf.der")
        val validation = ValidationResult(true, true, true, true, "OK")
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
    fun `format as text`() {
        val text = ResultFormatterImpl().formatAsText(listOf(sampleResult()))
        assertTrue(text.contains("example.com:443"))
        assertTrue(text.contains("TLSv1.3"))
    }

    @Test
    fun `format as json`() {
        val json = ResultFormatterImpl().formatAsJson(listOf(sampleResult()))
        assertTrue(json.contains("\"hostname\":\"example.com\""))
    }

    @Test
    fun `format as yaml`() {
        val yaml = ResultFormatterImpl().formatAsYaml(listOf(sampleResult()))
        assertTrue(yaml.contains("hostname: \"example.com\""))
    }
}
