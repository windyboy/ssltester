package org.example.formatter

import org.example.CertificateValidator
import org.example.model.SSLConnection

class TextOutputFormatter : OutputFormatter {
    override fun format(connection: SSLConnection): String {
        val sb = StringBuilder()
        sb.appendLine("SSL Test Result for ${connection.host}:${connection.port}")
        sb.appendLine("------------------------------")
        sb.appendLine("Protocol: ${connection.protocol}")
        sb.appendLine("Cipher Suite: ${connection.cipherSuite}")
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
        return sb.toString()
    }

    override fun getFileExtension(): String = "txt"
}
