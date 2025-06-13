package org.example.infrastructure.output

import org.example.domain.model.SSLConnection
import org.example.domain.service.OutputFormatter
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

    private fun getCertificateType(cert: X509Certificate): String {
        return try {
            val keyUsage = cert.keyUsage
            val extendedKeyUsage = cert.extendedKeyUsage
            
            when {
                keyUsage?.getOrNull(0) == true && keyUsage.getOrNull(5) == true -> "SSL/TLS服务器证书"
                keyUsage?.getOrNull(0) == true && keyUsage.getOrNull(5) == false -> "SSL/TLS客户端证书"
                extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.1") == true -> "SSL/TLS服务器证书"
                extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.2") == true -> "SSL/TLS客户端证书"
                extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.3") == true -> "代码签名证书"
                extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.4") == true -> "电子邮件保护证书"
                extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.8") == true -> "时间戳证书"
                keyUsage?.getOrNull(1) == true -> "CA证书"
                else -> "未知类型证书"
            }
        } catch (e: Exception) {
            "未知类型证书"
        }
    }

    override fun format(connection: SSLConnection): String {
        println("Debug: Formatting connection with ${connection.certificateChain.size} certificates")
        
        return buildString {
            try {
                // Header
                appendLine("${ANSI_BOLD}${ANSI_BG_BLUE}${ANSI_WHITE} SSL/TLS Connection Test Results ${ANSI_RESET}")
                appendLine("${ANSI_CYAN}${"═".repeat(60)}${ANSI_RESET}")
                
                // Basic Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Basic Information${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(60)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Host:${ANSI_RESET} ${ANSI_YELLOW}${connection.host}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Port:${ANSI_RESET} ${ANSI_YELLOW}${connection.port}${ANSI_RESET}")
                
                // Connection Status
                val statusColor = if (connection.isSecure) ANSI_BG_GREEN else ANSI_BG_RED
                val statusText = if (connection.isSecure) "✓ SECURE" else "✗ INSECURE"
                appendLine("\n${ANSI_BOLD}${ANSI_WHITE}${statusColor} $statusText ${ANSI_RESET}")
                
                // Protocol Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Protocol Information${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(60)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}Protocol:${ANSI_RESET} ${connection.protocol}")
                appendLine("${ANSI_BOLD}Cipher Suite:${ANSI_RESET} ${connection.cipherSuite}")
                appendLine("${ANSI_BOLD}Handshake Time:${ANSI_RESET} ${connection.handshakeTime.toMillis()}ms")
                
                // Certificate Information
                val certificates = connection.certificateChain
                println("Debug: Processing ${certificates.size} certificates")
                
                if (certificates.isEmpty()) {
                    appendLine("\n${ANSI_BOLD}${ANSI_RED}Certificate Chain: Empty${ANSI_RESET}")
                } else {
                    appendLine("\n${ANSI_BOLD}${ANSI_BLUE}Certificate Chain${ANSI_RESET}")
                    appendLine("${ANSI_BLUE}${"─".repeat(60)}${ANSI_RESET}")
                    
                    certificates.forEachIndexed { index, cert ->
                        try {
                            println("Debug: Formatting certificate ${index + 1}")
                            appendLine("${ANSI_BOLD}${ANSI_CYAN}Certificate ${index + 1}${ANSI_RESET}")
                            appendLine("${ANSI_BLUE}┌${"─".repeat(59)}${ANSI_RESET}")
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}类型:${ANSI_RESET} ${getCertificateType(cert)}")
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}主体:${ANSI_RESET} ${cert.subjectX500Principal}")
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}颁发者:${ANSI_RESET} ${cert.issuerX500Principal}")
                            
                            // 格式化证书有效期
                            val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                            val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}有效期:${ANSI_RESET} ${dateFormatter.format(notBefore)} 至 ${dateFormatter.format(notAfter)}")
                            
                            // 计算证书指纹
                            val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                            val fingerprintHex = fingerprint.joinToString(":") { "%02X".format(it) }
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}指纹(SHA-256):${ANSI_RESET} $fingerprintHex")
                            
                            appendLine("${ANSI_BLUE}└${"─".repeat(59)}${ANSI_RESET}")
                            if (index < certificates.size - 1) {
                                appendLine("${ANSI_BLUE}│${" ".repeat(59)}${ANSI_RESET}")
                            }
                        } catch (e: Exception) {
                            println("Debug: Error formatting certificate ${index + 1}: ${e.message}")
                            appendLine("${ANSI_BOLD}${ANSI_RED}Error formatting certificate ${index + 1}: ${e.message}${ANSI_RESET}")
                        }
                    }
                }
                
                // Footer
                appendLine("\n${ANSI_CYAN}${"═".repeat(60)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}${ANSI_CYAN}Test completed at: ${dateFormatter.format(LocalDateTime.now())}${ANSI_RESET}")
            } catch (e: Exception) {
                println("Debug: Error in format method: ${e.message}")
                e.printStackTrace()
                appendLine("${ANSI_BOLD}${ANSI_RED}Error formatting output: ${e.message}${ANSI_RESET}")
            }
        }
    }

    override fun getFileExtension(): String = "txt"
} 