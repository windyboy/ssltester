package org.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import network.oxalis.pkix.ocsp.CertificateResult
import network.oxalis.pkix.ocsp.OcspClient
import java.security.cert.X509Certificate

class CertificateValidator {
    data class ValidationResult(
        val isValid: Boolean,
        val revocationStatus: RevocationStatus,
        val errors: List<String> = emptyList(),
    )

    sealed class RevocationStatus {
        object Valid : RevocationStatus()

        data class Revoked(val reason: String) : RevocationStatus()

        object Unknown : RevocationStatus()

        data class Error(val message: String) : RevocationStatus()
    }

    suspend fun validateCertificateChain(certificates: List<X509Certificate>): ValidationResult =
        withContext(Dispatchers.IO) {
            if (certificates.isEmpty()) {
                ValidationResult(
                    isValid = false,
                    revocationStatus = RevocationStatus.Error("No certificates provided"),
                    errors = listOf("No certificates provided"),
                )
            } else if (certificates.size < 2) {
                ValidationResult(
                    isValid = true,
                    revocationStatus = RevocationStatus.Unknown,
                    errors = listOf("Certificate chain too short for OCSP validation"),
                )
            } else {
                val leaf = certificates[0]
                val issuer = certificates[1]
                try {
                    val ocspClientBuilder =
                        OcspClient.builder()
                            .set(OcspClient.EXCEPTION_ON_UNKNOWN, false)
                            .set(OcspClient.EXCEPTION_ON_REVOKED, false)
                    val ocspClient = ocspClientBuilder.build()
                    val result: CertificateResult = ocspClient.verify(leaf, issuer)
                    val status = result.status.toString().uppercase()

                    when (status) {
                        "GOOD" ->
                            ValidationResult(
                                isValid = true,
                                revocationStatus = RevocationStatus.Valid,
                                errors = emptyList(),
                            )
                        "REVOKED" ->
                            ValidationResult(
                                isValid = false,
                                revocationStatus = RevocationStatus.Revoked("Certificate revoked via OCSP"),
                                errors = emptyList(),
                            )
                        "UNKNOWN" ->
                            ValidationResult(
                                isValid = true,
                                revocationStatus = RevocationStatus.Unknown,
                                errors = emptyList(),
                            )
                        else ->
                            ValidationResult(
                                isValid = true,
                                revocationStatus = RevocationStatus.Unknown,
                                errors = listOf("Unknown OCSP status: ${result.status}"),
                            )
                    }
                } catch (e: Exception) {
                    ValidationResult(
                        isValid = true,
                        revocationStatus = RevocationStatus.Error("OCSP check failed: ${e.message}"),
                        errors = listOf("OCSP check failed: ${e.message}"),
                    )
                }
            }
        }
}
