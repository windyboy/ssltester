package org.example.output

import org.example.model.SSLConnection
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class TextOutputFormatter : OutputFormatter {
    private val ansiReset = "\u001B[0m"
    private val ansiGreen = "\u001B[32m"
    private val ansiRed = "\u001B[31m"
    private val ansiYellow = "\u001B[33m"
    private val ansiBlue = "\u001B[34m"
    private val ansiCyan = "\u001B[36m"
    private val ansiBold = "\u001B[1m"
    private val ansiWhite = "\u001B[37m"
    private val ansiBgBlue = "\u001B[44m"
    private val ansiBgGreen = "\u001B[42m"
    private val ansiBgRed = "\u001B[41m"

    private val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    private val maxLineLength = 80

    override fun format(connection: SSLConnection): String {
        return buildString {
            try {
                // Header
                appendLine("${ansiBold}${ansiBgBlue}$ansiWhite SSL/TLS Connection Test Results $ansiReset")
                appendLine("${ansiCyan}${"═".repeat(maxLineLength)}$ansiReset")

                // Basic Information
                appendLine("\n${ansiBold}${ansiBlue}Basic Information$ansiReset")
                appendLine("${ansiBlue}${"─".repeat(maxLineLength)}$ansiReset")
                appendLine("${ansiBold}Host:$ansiReset ${ansiYellow}${connection.host}$ansiReset")
                appendLine("${ansiBold}Port:$ansiReset ${ansiYellow}${connection.port}$ansiReset")

                // Connection Status
                val statusColor = if (connection.isSecure) ansiBgGreen else ansiBgRed
                val statusText = if (connection.isSecure) "✓ Secure" else "✗ Not Secure"
                appendLine("\n${ansiBold}${ansiWhite}$statusColor $statusText $ansiReset")

                // Protocol Information
                appendLine("\n${ansiBold}${ansiBlue}Protocol Information$ansiReset")
                appendLine("${ansiBlue}${"─".repeat(maxLineLength)}$ansiReset")
                appendLine("${ansiBold}Protocol Version:$ansiReset ${connection.protocol}")
                appendLine("${ansiBold}Cipher Suite:$ansiReset ${connection.cipherSuite}")
                appendLine("${ansiBold}Handshake Time:$ansiReset ${connection.handshakeTime.toMillis()}ms")

                // Certificate Information
                if (connection.certificateChain.isEmpty()) {
                    appendLine("\n${ansiBold}${ansiRed}Certificate Chain: Empty$ansiReset")
                } else {
                    appendLine("\n${ansiBold}${ansiBlue}Certificate Chain$ansiReset")
                    appendLine("${ansiBlue}${"─".repeat(maxLineLength)}$ansiReset")

                    connection.certificateChain.forEachIndexed { index, cert ->
                        formatCertificate(cert, index)?.let { appendLine(it) }
                    }
                }

                // Footer
                appendLine("\n${ansiCyan}${"═".repeat(maxLineLength)}$ansiReset")
                appendLine("${ansiBold}${ansiCyan}Test Completed: ${dateFormatter.format(LocalDateTime.now())}$ansiReset")
            } catch (e: Exception) {
                appendLine("${ansiBold}${ansiRed}Error formatting output: ${e.message}$ansiReset")
            }
        }
    }

    private fun formatCertificate(
        cert: X509Certificate,
        index: Int,
    ): String? {
        return try {
            buildString {
                appendLine("${ansiBold}${ansiCyan}Certificate ${index + 1}$ansiReset")
                appendLine("$ansiBlue┌${"─".repeat(maxLineLength - 2)}$ansiReset")

                // Subject
                wrapLongLine(cert.subjectX500Principal.toString()).forEach { line ->
                    appendLine("$ansiBlue│$ansiReset ${ansiBold}Subject:$ansiReset $line")
                }

                // Issuer
                wrapLongLine(cert.issuerX500Principal.toString()).forEach { line ->
                    appendLine("$ansiBlue│$ansiReset ${ansiBold}Issuer:$ansiReset $line")
                }

                // Validity
                val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                appendLine("$ansiBlue│$ansiReset ${ansiBold}Valid From:$ansiReset ${dateFormatter.format(notBefore)}")
                appendLine("$ansiBlue│$ansiReset ${ansiBold}Valid Until:$ansiReset ${dateFormatter.format(notAfter)}")

                // Fingerprint
                val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                val fingerprintHex = fingerprint.joinToString(":") { "%02X".format(it) }
                wrapLongLine(fingerprintHex).forEach { line ->
                    appendLine("$ansiBlue│$ansiReset ${ansiBold}SHA-256:$ansiReset $line")
                }

                appendLine("$ansiBlue└${"─".repeat(maxLineLength - 2)}$ansiReset")
            }
        } catch (e: Exception) {
            "${ansiBold}${ansiRed}Error formatting certificate ${index + 1}: ${e.message}$ansiReset"
        }
    }

    private fun wrapLongLine(
        text: String,
        maxLength: Int = maxLineLength - 20,
    ): List<String> {
        if (text.length <= maxLength) return listOf(text)

        return text.chunked(maxLength)
    }

    override fun getFileExtension(): String = "txt"
}
