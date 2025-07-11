package org.example.formatter

import org.example.SSLConstants
import org.example.model.SSLConnection
import java.security.cert.X509Certificate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Emoji文本格式输出格式化器。
 * 以带有emoji的文本方式输出 SSL 连接结果。
 */
class EmojiTextOutputFormatter : OutputFormatter {
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
                append("🔒 SSL证书信息 - ${connection.host}:${connection.port}\n")
                append("=".repeat(maxLineLength) + "\n")

                // Display certificate validation results first
                connection.certificateValidation?.let { validation ->
                    append("🔍 证书验证结果\n")
                    append("=".repeat(maxLineLength) + "\n")

                    val isValid = validation.isValid
                    val statusIcon = if (isValid) "✅" else "❌"
                    append("$statusIcon 验证状态: ${if (isValid) "有效" else "无效"}\n")

                    val revocationStatus =
                        when (val status = validation.revocationStatus) {
                            is org.example.CertificateValidator.RevocationStatus.Valid -> "✅ 有效"
                            is org.example.CertificateValidator.RevocationStatus.Revoked -> "❌ 已撤销: ${status.reason}"
                            is org.example.CertificateValidator.RevocationStatus.Unknown -> "❓ 未知"
                            is org.example.CertificateValidator.RevocationStatus.Error -> "⚠️  错误: ${status.message}"
                        }
                    append("🔄 撤销状态: $revocationStatus\n")

                    if (validation.errors.isNotEmpty()) {
                        append("⚠️  错误信息:\n")
                        validation.errors.forEach { error ->
                            append("   • $error\n")
                        }
                    }
                    append("\n")
                }

                // Basic Certificate Information
                if (connection.certificateChain.isNotEmpty()) {
                    val leafCert = connection.certificateChain.first()
                    formatBasicCertificateInfo(this, leafCert, connection)
                }

                // Certificate Chain Information
                if (connection.certificateChain.isNotEmpty()) {
                    append("\n")
                    append("🔗 证书链信息 (共 ${connection.certificateChain.size} 个证书)\n")
                    append("=".repeat(maxLineLength) + "\n")

                    connection.certificateChain.forEachIndexed { index, cert ->
                        formatCertificateChainInfo(this, cert, index + 1)
                    }
                }
            } catch (e: Exception) {
                append("❌ 格式化输出时出错: ${e.message}\n")
            }
        }
    }

    private fun formatBasicCertificateInfo(
        sb: StringBuilder,
        cert: X509Certificate,
        connection: SSLConnection,
    ) {
        // Subject
        val subject = extractCommonName(cert.subjectX500Principal.name) ?: "未知"
        sb.append("📋 主题: $subject\n")

        // Issuer
        val issuer = extractCommonName(cert.issuerX500Principal.name) ?: "未知"
        sb.append("🏢 颁发者: $issuer\n")

        // Validity Period
        val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
        val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
        sb.append("📅 有效期: ${dateFormatter.format(notBefore)} 至 ${dateFormatter.format(notAfter)}\n")

        // Status
        val now = LocalDateTime.now()
        val daysUntilExpiry = java.time.Duration.between(now, notAfter).toDays()
        val status =
            when {
                daysUntilExpiry < 0 -> "❌ 已过期"
                daysUntilExpiry <= 30 -> "⚠️  即将过期 ($daysUntilExpiry 天后过期)"
                else -> "✅ 有效 ($daysUntilExpiry 天后过期)"
            }
        sb.append("✅ 状态: $status\n")

        // DNS Names
        val dnsNames = extractDNSNames(cert)
        if (dnsNames.isNotEmpty()) {
            sb.append("🌐 DNS名称: ${dnsNames.joinToString(", ")}\n")
        }

        // Signature Algorithm
        sb.append("🔐 签名算法: ${cert.sigAlgName}\n")

        // Public Key Algorithm
        val keyAlgorithm = cert.publicKey.algorithm
        val keySize = cert.publicKey.encoded.size * 8
        sb.append("🗝️  公钥算法: $keyAlgorithm ($keySize 位)\n")

        // Security Features
        sb.append("🛡️  安全特性: 🔸 证书透明度\n")

        // Separator
        sb.append("-".repeat(maxLineLength) + "\n")

        // Detailed Information
        sb.append("📊 详细信息:\n")

        // Serial Number
        sb.append("   🔢 序列号: ${cert.serialNumber}\n")

        // Version
        sb.append("   📊 版本: ${cert.version}\n")

        // Total Validity Period
        val totalDays = java.time.Duration.between(notBefore, notAfter).toDays()
        sb.append("   ⏰ 证书总有效期: $totalDays 天\n")

        // Used Time
        val usedDays = java.time.Duration.between(notBefore, now).toDays()
        sb.append("   ⏱️  已使用时间: $usedDays 天\n")
    }

    private fun formatCertificateChainInfo(
        sb: StringBuilder,
        cert: X509Certificate,
        index: Int,
    ) {
        sb.append("📜 证书 $index:\n")

        val subject = extractCommonName(cert.subjectX500Principal.name) ?: "未知"
        sb.append("   主题: $subject\n")

        val issuer = extractCommonName(cert.issuerX500Principal.name) ?: "未知"
        sb.append("   颁发者: $issuer\n")

        val notBefore = cert.notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
        val notAfter = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
        sb.append("   有效期: ${dateFormatter.format(notBefore).split(" ")[0]} 至 ${dateFormatter.format(notAfter).split(" ")[0]}\n")

        // Check if it's a CA certificate
        val keyUsage = cert.keyUsage
        if (keyUsage != null && keyUsage[5]) { // keyCertSign bit
            sb.append("   🔸 CA证书\n")
        }

        sb.append("\n")
    }

    private fun extractCommonName(subject: String): String? {
        return try {
            val ldapName = javax.naming.ldap.LdapName(subject)
            for (rdn in ldapName.rdns) {
                if (rdn.type.equals("CN", ignoreCase = true)) {
                    return rdn.value.toString()
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun extractDNSNames(cert: X509Certificate): List<String> {
        val dnsNames = mutableListOf<String>()
        try {
            val sans = cert.subjectAlternativeNames
            if (sans != null) {
                for (san in sans) {
                    val type = san[0] as Int
                    val value = san[1] as String
                    if (type == 2) { // DNS type
                        dnsNames.add(value)
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore errors
        }
        return dnsNames
    }

    /**
     * 获取文件扩展名。
     */
    override fun getFileExtension(): String = "txt"
}
