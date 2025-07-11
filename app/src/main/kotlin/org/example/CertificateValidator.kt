package org.example

import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import javax.naming.ldap.LdapName

/**
 * Certificate validation and analysis utilities.
 * Provides comprehensive certificate validation including hostname verification,
 * expiry checking, and security analysis.
 */
class CertificateValidator {
    /**
     * Certificate validation result.
     */
    data class ValidationResult(
        val isValid: Boolean,
        val issues: List<String> = emptyList(),
        val warnings: List<String> = emptyList(),
        val daysUntilExpiry: Long? = null,
        val isHostnameValid: Boolean = false,
        val certificateStrength: CertificateStrength = CertificateStrength.UNKNOWN,
    )

    /**
     * Certificate strength classification.
     */
    enum class CertificateStrength {
        WEAK, // < 2048 bits
        MEDIUM, // 2048 bits
        STRONG, // > 2048 bits
        UNKNOWN, // Unable to determine
    }

    /**
     * Validates a certificate chain for a given hostname.
     */
    fun validateCertificateChain(
        certificates: List<X509Certificate>,
        hostname: String,
    ): ValidationResult {
        if (certificates.isEmpty()) {
            return ValidationResult(
                isValid = false,
                issues = listOf("No certificates provided"),
            )
        }

        val leafCertificate = certificates.first()
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        // Check certificate expiry
        val expiryResult = checkCertificateExpiry(leafCertificate)
        if (!expiryResult.isValid) {
            issues.add(expiryResult.issue ?: "Certificate expiry check failed")
        } else if (expiryResult.warning != null) {
            warnings.add(expiryResult.warning)
        }

        // Check hostname verification
        val isHostnameValid = verifyHostname(leafCertificate, hostname)
        if (!isHostnameValid) {
            issues.add("Hostname verification failed: certificate does not match '$hostname'")
        }

        // Check certificate strength
        val strength = analyzeCertificateStrength(leafCertificate)

        // Check certificate chain validity
        if (certificates.size > 1) {
            val chainIssues = validateCertificateChain(certificates)
            issues.addAll(chainIssues)
        }

        return ValidationResult(
            isValid = issues.isEmpty(),
            issues = issues,
            warnings = warnings,
            daysUntilExpiry = expiryResult.daysUntilExpiry,
            isHostnameValid = isHostnameValid,
            certificateStrength = strength,
        )
    }

    /**
     * Checks if a certificate is expired or expiring soon.
     */
    private fun checkCertificateExpiry(certificate: X509Certificate): ExpiryResult {
        val now = Instant.now()
        val notAfter = certificate.notAfter.toInstant()
        val daysUntilExpiry = Duration.between(now, notAfter).toDays()

        return when {
            now.isAfter(notAfter) ->
                ExpiryResult(
                    isValid = false,
                    issue = "Certificate expired on ${certificate.notAfter}",
                    daysUntilExpiry = daysUntilExpiry,
                )
            daysUntilExpiry <= 30 ->
                ExpiryResult(
                    isValid = true,
                    warning = "Certificate expires in $daysUntilExpiry days (${certificate.notAfter})",
                    daysUntilExpiry = daysUntilExpiry,
                )
            else ->
                ExpiryResult(
                    isValid = true,
                    daysUntilExpiry = daysUntilExpiry,
                )
        }
    }

    /**
     * Verifies if the certificate's subject matches the hostname.
     */
    fun verifyHostname(
        certificate: X509Certificate,
        hostname: String,
    ): Boolean {
        return try {
            // Check Subject Alternative Names (SAN)
            val sans = certificate.subjectAlternativeNames
            if (sans != null) {
                for (san in sans) {
                    val type = san[0] as Int
                    val value = san[1] as String

                    if (type == 2 && matchesHostname(value, hostname)) { // DNS type
                        return true
                    }
                }
            }

            // Check Common Name (CN) in subject
            val subject = certificate.subjectX500Principal.toString()
            val cn = extractCommonName(subject)
            if (cn != null && matchesHostname(cn, hostname)) {
                return true
            }

            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Extracts Common Name from X.500 subject string.
     */
    private fun extractCommonName(subject: String): String? {
        return try {
            val ldapName = LdapName(subject)
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

    /**
     * Checks if a certificate hostname matches the target hostname.
     */
    private fun matchesHostname(
        certHostname: String,
        targetHostname: String,
    ): Boolean {
        return certHostname.equals(targetHostname, ignoreCase = true) ||
            certHostname.startsWith("*.") &&
            targetHostname.endsWith(certHostname.substring(2), ignoreCase = true)
    }

    /**
     * Analyzes the cryptographic strength of a certificate.
     */
    private fun analyzeCertificateStrength(certificate: X509Certificate): CertificateStrength {
        return try {
            val publicKey = certificate.publicKey
            val keySize = when (publicKey.algorithm) {
                "RSA" -> {
                    val rsaKey = publicKey as java.security.interfaces.RSAPublicKey
                    rsaKey.modulus.bitLength()
                }
                "EC" -> {
                    val ecKey = publicKey as java.security.interfaces.ECPublicKey
                    ecKey.params.curve.field.fieldSize
                }
                "DSA" -> {
                    val dsaKey = publicKey as java.security.interfaces.DSAPublicKey
                    dsaKey.params.p.bitLength()
                }
                else -> {
                    // Fallback to encoded size method for unknown algorithms
                    publicKey.encoded.size * 8
                }
            }
            
            when {
                keySize < 2048 -> CertificateStrength.WEAK
                keySize == 2048 -> CertificateStrength.MEDIUM
                keySize > 2048 -> CertificateStrength.STRONG
                else -> CertificateStrength.UNKNOWN
            }
        } catch (e: Exception) {
            CertificateStrength.UNKNOWN
        }
    }

    /**
     * Validates the certificate chain (signature verification).
     */
    private fun validateCertificateChain(certificates: List<X509Certificate>): List<String> {
        val issues = mutableListOf<String>()

        for (i in 0 until certificates.size - 1) {
            val cert = certificates[i]
            val issuer = certificates[i + 1]

            try {
                cert.verify(issuer.publicKey)
            } catch (e: Exception) {
                issues.add("Certificate chain validation failed at position $i: ${e.message}")
            }
        }

        return issues
    }

    /**
     * Expiry check result.
     */
    private data class ExpiryResult(
        val isValid: Boolean,
        val issue: String? = null,
        val warning: String? = null,
        val daysUntilExpiry: Long? = null,
    )
}
