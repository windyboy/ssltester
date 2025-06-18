package org.example.output

import org.example.model.SSLConnection
import java.security.cert.X509Certificate
import java.time.format.DateTimeFormatter
import java.time.ZoneId
import java.time.LocalDateTime
import java.security.MessageDigest

class TextOutputFormatter : OutputFormatter {
    private val ANSI_RESET = "\u001B[0m"
    private val ANSI_GREEN = "\u001B[32m"
    private val ANSI_RED = "\u001B[31m"
    private val ANSI_YELLOW = "\u001B[33m"
    private val ANSI_BLUE = "\u001B[34m"
    private val ANSI_CYAN = "\u001B[36m"
    private val ANSI_BOLD = "\u001B[1m"
    private val ANSI_WHITE = "\u001B[37m"
    private val ANSI_BG_BLUE = "\u001B[44m"
    private val ANSI_BG_GREEN = "\u001B[42m"
    private val ANSI_BG_RED = "\u001B[41m"

    private val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    private val MAX_LINE_LENGTH = 80

    override fun format(connection: SSLConnection): String {
        return buildString {
            try {
                // Header
                appendLine("${ANSI_BOLD}${ANSI_BG_BLUE}${ANSI_WHITE} SSL/TLS Connection Test Results ${ANSI_RESET}")
                appendLine("${ANSI_CYAN}${"═".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                
                // Basic Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Basic Information${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Host:${ANSI_RESET} ${ANSI_YELLOW}${connection.host}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Port:${ANSI_RESET} ${ANSI_YELLOW}${connection.port}${ANSI_RESET}")
                
                // Connection Status
                val statusColor = if (connection.isSecure) ANSI_BG_GREEN else ANSI_BG_RED
                val statusText = if (connection.isSecure) "✓ Secure" else "✗ Not Secure"
                appendLine("\n${ANSI_BOLD}${ANSI_WHITE}${statusColor} $statusText ${ANSI_RESET}")
                
                // Protocol Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Protocol Information${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Protocol Version:${ANSI_RESET} ${connection.protocol}")
                appendLine("${ANSI_BOLD}Cipher Suite:${ANSI_RESET} ${connection.cipherSuite}")
                appendLine("${ANSI_BOLD}Handshake Time:${ANSI_RESET} ${connection.handshakeTime.toMillis()}ms")
                
                // Certificate Information
                if (connection.certificateChain.isEmpty()) {
                    appendLine("\n${ANSI_BOLD}${ANSI_RED}Certificate Chain: Empty${ANSI_RESET}")
                } else {
                    appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Certificate Chain${ANSI_RESET}")
                    appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                    
                    connection.certificateChain.forEachIndexed { index, cert ->
                        formatCertificate(cert, index)?.let { appendLine(it) }
                    }
                }
                
                // Footer
                appendLine("\n${ANSI_CYAN}${"═".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}${ANSI_CYAN}Test Completed: ${dateFormatter.format(LocalDateTime.now())}${ANSI_RESET}")
            } catch (e: Exception) {
                appendLine("${ANSI_BOLD}${ANSI_RED}Error formatting output: ${e.message}${ANSI_RESET}")
            }
        }
    }

    private fun formatCertificate(cert: X509Certificate, index: Int): String? {
        return try {
            buildString {
                appendLine("${ANSI_BOLD}${ANSI_CYAN}Certificate ${index + 1}${ANSI_RESET}")
                appendLine("${ANSI_BLUE}┌${"─".repeat(MAX_LINE_LENGTH - 2)}${ANSI_RESET}")
                
                // Subject
                wrapLongLine(cert.subjectX500Principal.toString()).forEach { line ->
                    appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}Subject:${ANSI_RESET} $line")
                }
                
                // Issuer
                wrapLongLine(cert.issuerX500Principal.toString()).forEach { line ->
                    appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}Issuer:${ANSI_RESET} $line")
                }
                
                // Validity
                val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}Valid From:${ANSI_RESET} ${dateFormatter.format(notBefore)}")
                appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}Valid Until:${ANSI_RESET} ${dateFormatter.format(notAfter)}")
                
                // Fingerprint
                val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                val fingerprintHex = fingerprint.joinToString(":") { "%02X".format(it) }
                wrapLongLine(fingerprintHex).forEach { line ->
                    appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}SHA-256:${ANSI_RESET} $line")
                }
                
                appendLine("${ANSI_BLUE}└${"─".repeat(MAX_LINE_LENGTH - 2)}${ANSI_RESET}")
            }
        } catch (e: Exception) {
            "${ANSI_BOLD}${ANSI_RED}Error formatting certificate ${index + 1}: ${e.message}${ANSI_RESET}"
        }
    }

    private fun wrapLongLine(text: String, maxLength: Int = MAX_LINE_LENGTH - 20): List<String> {
        if (text.length <= maxLength) return listOf(text)
        
        return text.chunked(maxLength)
    }

    override fun getFileExtension(): String = "txt"
} 