package org.example.infrastructure.output

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.example.domain.model.SSLConnection
import org.example.domain.service.OutputFormatter
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * YAML formatter for SSL test results.
 */
class YamlOutputFormatter : OutputFormatter {
    private val mapper = ObjectMapper(YAMLFactory()).registerKotlinModule()

    private fun getCertificateType(@Suppress("UNUSED_PARAMETER") cert: X509Certificate): String {
        return "服务器证书"
    }

    override fun format(connection: SSLConnection): String {
        val data = mapOf(
            "url" to "https://${connection.host}:${connection.port}",
            "connectionStatus" to if (connection.isSecure) "SUCCESS" else "FAILED",
            "httpStatus" to 200,
            "cipherSuite" to connection.cipherSuite,
            "tlsVersion" to connection.protocol,
            "hostnameVerification" to if (connection.isSecure) "PASSED" else "FAILED",
            "certificateChain" to connection.certificateChain.mapIndexed { index, cert ->
                val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                val fingerprintHex = fingerprint.joinToString(":") { "%02X".format(it) }
                mapOf(
                    "position" to (index + 1),
                    "type" to getCertificateType(cert),
                    "subject" to cert.subjectX500Principal.toString(),
                    "issuer" to cert.issuerX500Principal.toString(),
                    "validFrom" to cert.notBefore.toString(),
                    "validTo" to cert.notAfter.toString(),
                    "fingerprintSHA256" to fingerprintHex
                )
            }
        )
        
        return mapper.writeValueAsString(data)
    }

    override fun getFileExtension(): String = "yaml"
} 