package org.example.output

import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import org.example.model.SSLTestResult
import org.slf4j.LoggerFactory
import java.io.File
import java.io.PrintWriter
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.SerializationFeature
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Implementation of result formatting and output.
 */
class ResultFormatterImpl : ResultFormatter {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val jsonMapper = ObjectMapper().apply { 
        registerKotlinModule()
        configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
        addMixIn(X509Certificate::class.java, CertificateMixin::class.java)
    }
    private val yamlMapper = ObjectMapper(YAMLFactory()).apply { 
        registerKotlinModule()
        configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
        addMixIn(X509Certificate::class.java, CertificateMixin::class.java)
    }

    override fun formatAndOutput(results: List<SSLTestResult>, config: SSLTestConfig) {
        try {
            val format = config.outputFormat ?: throw SSLTestException("Invalid output format")
            val outputFile = config.outputFile

            val output = when (format) {
                SSLTestConfig.OutputFormat.TEXT -> formatAsText(results)
                SSLTestConfig.OutputFormat.JSON -> formatAsJson(results)
                SSLTestConfig.OutputFormat.YAML -> formatAsYaml(results)
            }

            if (outputFile != null) {
                File(outputFile).writeText(output)
            } else {
                println(output)
            }
        } catch (e: Exception) {
            logger.error("Failed to format and output results: ${e.message}", e)
            throw SSLTestException("Failed to format and output results: ${e.message}")
        }
    }

    override fun formatAsText(results: List<SSLTestResult>): String {
        if (results.isEmpty()) {
            return "No SSL test results to display."
        }

        return buildString {
            results.forEach { result ->
                appendLine("SSL Test Result for ${result.hostname}:${result.port}")
                appendLine("Protocol: ${result.protocol}")
                appendLine("Cipher Suite: ${result.cipherSuite}")
                appendLine("Certificate Chain:")
                result.certificateChain.forEachIndexed { index, cert ->
                    appendLine("  Certificate ${index + 1}:")
                    appendLine("    Subject: ${cert.subjectX500Principal.name}")
                    appendLine("    Issuer: ${cert.issuerX500Principal.name}")
                    appendLine("    Valid Until: ${cert.notAfter}")
                }
                appendLine("Validation Result:")
                appendLine("  Valid: ${result.validationResult.chainValidationResult && result.validationResult.hostnameValidationResult}")
                appendLine("  Message: ${result.validationResult.message}")
                appendLine()
            }
        }.trim()
    }

    override fun formatAsJson(results: List<SSLTestResult>): String {
        return jsonMapper.writeValueAsString(results)
    }

    override fun formatAsYaml(results: List<SSLTestResult>): String {
        return yamlMapper.writeValueAsString(results)
    }
}

/**
 * Mixin class for X509Certificate serialization.
 */
abstract class CertificateMixin {
    @JsonProperty("subject")
    abstract fun getSubjectX500Principal(): javax.security.auth.x500.X500Principal

    @JsonProperty("issuer")
    abstract fun getIssuerX500Principal(): javax.security.auth.x500.X500Principal

    @JsonProperty("notBefore")
    abstract fun getNotBefore(): java.util.Date

    @JsonProperty("notAfter")
    abstract fun getNotAfter(): java.util.Date

    @JsonProperty("serialNumber")
    abstract fun getSerialNumber(): java.math.BigInteger

    @JsonProperty("encoded")
    fun getEncoded(cert: X509Certificate): String {
        return Base64.getEncoder().encodeToString(cert.encoded)
    }
} 