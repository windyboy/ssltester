package org.example.domain.model

import java.security.cert.X509Certificate

data class SSLConnectionResult(
    val isSuccessful: Boolean,
    val protocol: String?,
    val cipherSuite: String?,
    val certificate: X509Certificate?,
    val error: Exception?
) 