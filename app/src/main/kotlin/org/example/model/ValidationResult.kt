package org.example.model

/**
 * Represents the result of certificate validation.
 */
data class ValidationResult(
    val chainValidationResult: Boolean,
    val hostnameValidationResult: Boolean,
    val revocationResult: Boolean,
    val ocspResult: Boolean,
    val message: String
) 