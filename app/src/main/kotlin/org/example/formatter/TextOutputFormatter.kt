package org.example.formatter

import org.example.CertificateValidator
import org.example.SSLConstants
import org.example.model.SSLConnection
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * 文本格式输出格式化器。
 * 以彩色文本方式输出 SSL 连接结果。
 */
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
    private val maxLineLength = SSLConstants.MAX_LINE_LENGTH

    /**
     * 格式化 SSL 连接结果为文本。
     * @param connection SSL 连接结果
     * @return 格式化后的文本
     */
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

                // Certificate Validation Results
                connection.certificateValidation?.let { validation ->
                    appendLine("\n${ansiBold}${ansiBlue}Certificate Validation$ansiReset")
                    appendLine("${ansiBlue}${"─".repeat(maxLineLength)}$ansiReset")

                    if (validation.isValid) {
                        appendLine("${ansiBold}$ansiGreen✓ Certificate is valid$ansiReset")
                    } else {
                        appendLine("${ansiBold}$ansiRed✗ Certificate validation failed$ansiReset")
                    }

                    if (validation.isHostnameValid) {
                        appendLine("${ansiBold}$ansiGreen✓ Hostname verification passed$ansiReset")
                    } else {
                        appendLine("${ansiBold}$ansiRed✗ Hostname verification failed$ansiReset")
                    }

                    validation.certificateStrength?.let { strength ->
                        val strengthColor =
                            when (strength) {
                                CertificateValidator.CertificateStrength.STRONG -> ansiGreen
                                CertificateValidator.CertificateStrength.MEDIUM -> ansiYellow
                                CertificateValidator.CertificateStrength.WEAK -> ansiRed
                                CertificateValidator.CertificateStrength.UNKNOWN -> ansiYellow
                            }
                        appendLine("${ansiBold}Certificate Strength:$ansiReset $strengthColor$strength$ansiReset")
                    }

                    validation.daysUntilExpiry?.let { days ->
                        val expiryColor =
                            when {
                                days < 0 -> ansiRed
                                days <= 30 -> ansiYellow
                                else -> ansiGreen
                            }
                        appendLine("${ansiBold}Days until expiry:$ansiReset $expiryColor$days days$ansiReset")
                    }

                    if (validation.issues.isNotEmpty()) {
                        appendLine("\n${ansiBold}${ansiRed}Issues:$ansiReset")
                        validation.issues.forEach { issue ->
                            appendLine("$ansiRed• $issue$ansiReset")
                        }
                    }

                    if (validation.warnings.isNotEmpty()) {
                        appendLine("\n${ansiBold}${ansiYellow}Warnings:$ansiReset")
                        validation.warnings.forEach { warning ->
                            appendLine("$ansiYellow• $warning$ansiReset")
                        }
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
        maxLength: Int = SSLConstants.CERTIFICATE_WRAP_LENGTH,
    ): List<String> {
        if (text.length <= maxLength) return listOf(text)

        return text.chunked(maxLength)
    }

    /**
     * 获取文件扩展名。
     */
    override fun getFileExtension(): String = "txt"
}
