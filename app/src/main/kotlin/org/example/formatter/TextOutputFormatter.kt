package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection
import java.security.cert.X509Certificate
import java.util.Date

class TextOutputFormatter : OutputFormatter {
    override fun format(connection: SSLConnection): String {
        val sb = StringBuilder()
        sb.appendLine("SSL Test Result for ${connection.host}:${connection.port}")
        sb.appendLine("------------------------------")
        sb.appendLine("Protocol: ${connection.protocol}")
        sb.appendLine("Cipher Suite: ${connection.cipherSuite}")

        // Display certificate validation results first
        connection.certificateValidation?.let { validation ->
            sb.appendLine("\nCertificate Validation")
            sb.appendLine("------------------------------")
            sb.appendLine("Valid: ${validation.isValid}")
            sb.appendLine(
                "Revocation Status: " +
                    when (val status = validation.revocationStatus) {
                        is CertificateValidator.RevocationStatus.Valid -> "Valid"
                        is CertificateValidator.RevocationStatus.Revoked -> "Revoked: ${status.reason}"
                        is CertificateValidator.RevocationStatus.Unknown -> "Unknown"
                        is CertificateValidator.RevocationStatus.Error -> "Error: ${status.message}"
                    },
            )
            if (validation.errors.isNotEmpty()) {
                sb.appendLine("Errors:")
                validation.errors.forEach { sb.appendLine("- $it") }
            }
        }

        // Display certificate chain information after validation
        if (connection.certificateChain.isNotEmpty()) {
            sb.appendLine("\nCertificate Chain")
            sb.appendLine("------------------------------")
            connection.certificateChain.forEachIndexed { index, cert ->
                sb.appendLine("Certificate ${index + 1}:")
                sb.appendLine("  Subject: ${cert.subjectX500Principal}")
                sb.appendLine("  Issuer: ${cert.issuerX500Principal}")
                sb.appendLine("  Serial Number: ${cert.serialNumber}")
                sb.appendLine("  Valid From: ${formatDate(cert.notBefore)}")
                sb.appendLine("  Valid Until: ${formatDate(cert.notAfter)}")
                sb.appendLine("  Signature Algorithm: ${cert.sigAlgName}")
                sb.appendLine("  Public Key Algorithm: ${cert.publicKey.algorithm}")
                sb.appendLine("  Key Size: ${cert.publicKey.encoded.size * 8} bits")

                // Display DNS names if available
                val dnsNames = extractDNSNames(cert)
                if (dnsNames.isNotEmpty()) {
                    sb.appendLine("  DNS Names: ${dnsNames.joinToString(", ")}")
                }

                // Display IP addresses if available
                val ipAddresses = extractIPAddresses(cert)
                if (ipAddresses.isNotEmpty()) {
                    sb.appendLine("  IP Addresses: ${ipAddresses.joinToString(", ")}")
                }

                if (index < connection.certificateChain.size - 1) {
                    sb.appendLine()
                }
            }
        }
        return sb.toString()
    }

    override fun getFileExtension(): String = "txt"

    private fun formatDate(date: Date): String {
        return try {
            val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
            sdf.format(date)
        } catch (e: Exception) {
            date.toString()
        }
    }

    private fun extractDNSNames(cert: X509Certificate): List<String> {
        return try {
            val sans = cert.getSubjectAlternativeNames()
            sans?.mapNotNull { san ->
                val type = san[0] as? Int
                val value = san[1] as? String
                if (type == 2) value else null // Type 2 is DNS name
            } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun extractIPAddresses(cert: X509Certificate): List<String> {
        return try {
            val sans = cert.getSubjectAlternativeNames()
            sans?.mapNotNull { san ->
                val type = san[0] as? Int
                val value = san[1] as? String
                if (type == 7) value else null // Type 7 is IP address
            } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
