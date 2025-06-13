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
    private val MAX_LINE_LENGTH = 80

    private fun getCertificateType(@Suppress("UNUSED_PARAMETER") cert: X509Certificate): String {
        return "服务器证书"
    }

    private fun wrapLongLine(text: String, prefix: String = ""): List<String> {
        if (text.length <= MAX_LINE_LENGTH - prefix.length) {
            return listOf(text)
        }
        
        val words = text.split(" ")
        val lines = mutableListOf<String>()
        var currentLine = StringBuilder()
        
        for (word in words) {
            if (currentLine.length + word.length + 1 <= MAX_LINE_LENGTH - prefix.length) {
                if (currentLine.isNotEmpty()) {
                    currentLine.append(" ")
                }
                currentLine.append(word)
            } else {
                lines.add(currentLine.toString())
                currentLine = StringBuilder(prefix + word)
            }
        }
        
        if (currentLine.isNotEmpty()) {
            lines.add(currentLine.toString())
        }
        
        return lines
    }

    override fun format(connection: SSLConnection): String {
        return buildString {
            try {
                // Header
                appendLine("${ANSI_BOLD}${ANSI_BG_BLUE}${ANSI_WHITE} SSL/TLS 连接测试结果 ${ANSI_RESET}")
                appendLine("${ANSI_CYAN}${"═".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                
                // Basic Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}基本信息${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}主机:${ANSI_RESET} ${ANSI_YELLOW}${connection.host}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}端口:${ANSI_RESET} ${ANSI_YELLOW}${connection.port}${ANSI_RESET}")
                
                // Connection Status
                val statusColor = if (connection.isSecure) ANSI_BG_GREEN else ANSI_BG_RED
                val statusText = if (connection.isSecure) "✓ 安全" else "✗ 不安全"
                appendLine("\n${ANSI_BOLD}${ANSI_WHITE}${statusColor} $statusText ${ANSI_RESET}")
                
                // Protocol Information
                appendLine("\n${ANSI_BOLD}${ANSI_BLUE}协议信息${ANSI_RESET}")
                appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}协议版本:${ANSI_RESET} ${connection.protocol}")
                appendLine("${ANSI_BOLD}加密套件:${ANSI_RESET} ${connection.cipherSuite}")
                appendLine("${ANSI_BOLD}握手时间:${ANSI_RESET} ${connection.handshakeTime.toMillis()}ms")
                
                // Certificate Information
                val certificates = connection.certificateChain
                
                if (certificates.isEmpty()) {
                    appendLine("\n${ANSI_BOLD}${ANSI_RED}证书链: 空${ANSI_RESET}")
                } else {
                    appendLine("\n${ANSI_BOLD}${ANSI_BLUE}证书链${ANSI_RESET}")
                    appendLine("${ANSI_BLUE}${"─".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                    
                    certificates.forEachIndexed { index, cert ->
                        try {
                            appendLine("${ANSI_BOLD}${ANSI_CYAN}证书 ${index + 1}${ANSI_RESET}")
                            appendLine("${ANSI_BLUE}┌${"─".repeat(MAX_LINE_LENGTH - 2)}${ANSI_RESET}")
                            
                            // 类型
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}类型:${ANSI_RESET} ${getCertificateType(cert)}")
                            
                            // 主体
                            val subjectLines = wrapLongLine(cert.subjectX500Principal.toString(), "${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}主体:${ANSI_RESET} ")
                            subjectLines.forEach { line ->
                                appendLine("${ANSI_BLUE}│${ANSI_RESET} ${if (line == subjectLines.first()) "" else "  "}$line")
                            }
                            
                            // 颁发者
                            val issuerLines = wrapLongLine(cert.issuerX500Principal.toString(), "${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}颁发者:${ANSI_RESET} ")
                            issuerLines.forEach { line ->
                                appendLine("${ANSI_BLUE}│${ANSI_RESET} ${if (line == issuerLines.first()) "" else "  "}$line")
                            }
                            
                            // 有效期
                            val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                            val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
                            appendLine("${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}有效期:${ANSI_RESET} ${dateFormatter.format(notBefore)} 至 ${dateFormatter.format(notAfter)}")
                            
                            // 指纹
                            val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                            val fingerprintHex = fingerprint.joinToString(":") { "%02X".format(it) }
                            val fingerprintLines = wrapLongLine(fingerprintHex, "${ANSI_BLUE}│${ANSI_RESET} ${ANSI_BOLD}指纹(SHA-256):${ANSI_RESET} ")
                            fingerprintLines.forEach { line ->
                                appendLine("${ANSI_BLUE}│${ANSI_RESET} ${if (line == fingerprintLines.first()) "" else "  "}$line")
                            }
                            
                            appendLine("${ANSI_BLUE}└${"─".repeat(MAX_LINE_LENGTH - 2)}${ANSI_RESET}")
                            
                            // 在证书之间添加空行
                            if (index < certificates.size - 1) {
                                appendLine()
                            }
                        } catch (e: Exception) {
                            appendLine("${ANSI_BOLD}${ANSI_RED}格式化证书 ${index + 1} 时出错: ${e.message}${ANSI_RESET}")
                        }
                    }
                }
                
                // Footer
                appendLine("\n${ANSI_CYAN}${"═".repeat(MAX_LINE_LENGTH)}${ANSI_RESET}")
                appendLine("${ANSI_BOLD}${ANSI_CYAN}测试完成时间: ${dateFormatter.format(LocalDateTime.now())}${ANSI_RESET}")
            } catch (e: Exception) {
                appendLine("${ANSI_BOLD}${ANSI_RED}格式化输出时出错: ${e.message}${ANSI_RESET}")
            }
        }
    }

    override fun getFileExtension(): String = "txt"
} 