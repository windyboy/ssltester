package org.example.cert

import org.example.model.ValidationResult
import java.security.cert.X509Certificate

/**
 * Interface for certificate validation.
 */
interface CertificateValidator {
    fun validateCertificates(certificates: List<X509Certificate>, hostname: String): ValidationResult
    fun validateCertificateChain(certificates: Array<X509Certificate>, hostname: String): Boolean
    fun verifyHostname(certificate: X509Certificate, hostname: String): Boolean
}