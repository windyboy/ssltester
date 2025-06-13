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

    private fun getCertificateType(cert: X509Certificate): String {
        val keyUsage = cert.keyUsage
        val extendedKeyUsage = cert.extendedKeyUsage
        
        return when {
            keyUsage?.get(0) == true && keyUsage.get(5) == true -> "SSL/TLS服务器证书"
            keyUsage?.get(0) == true && keyUsage.get(5) == false -> "SSL/TLS客户端证书"
            extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.1") == true -> "SSL/TLS服务器证书"
            extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.2") == true -> "SSL/TLS客户端证书"
            extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.3") == true -> "代码签名证书"
            extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.4") == true -> "电子邮件保护证书"
            extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.8") == true -> "时间戳证书"
            keyUsage?.get(1) == true -> "CA证书"
            else -> "未知类型证书"
        }
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