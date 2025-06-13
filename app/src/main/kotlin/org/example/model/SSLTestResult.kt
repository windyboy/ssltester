package org.example.model

import java.security.cert.X509Certificate

/**
 * Result of an SSL connection test.
 */
data class SSLTestResult(
    val hostname: String,
    val port: Int,
    val protocol: String,
    val cipherSuite: String,
    val certificateChain: List<X509Certificate>,
    val validationResult: ValidationResult
) {
    /**
     * Returns whether all validation checks passed.
     */
    val isValid: Boolean
        get() = validationResult.chainValidationResult && validationResult.hostnameValidationResult && validationResult.revocationResult && validationResult.ocspResult

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SSLTestResult) return false

        return hostname == other.hostname &&
            port == other.port &&
            protocol == other.protocol &&
            cipherSuite == other.cipherSuite &&
            certificateChain == other.certificateChain &&
            validationResult == other.validationResult
    }

    override fun hashCode(): Int {
        var result = hostname.hashCode()
        result = 31 * result + port
        result = 31 * result + protocol.hashCode()
        result = 31 * result + cipherSuite.hashCode()
        result = 31 * result + certificateChain.hashCode()
        result = 31 * result + validationResult.hashCode()
        return result
    }
} 