package org.example.domain.model

import java.security.cert.X509Certificate
import java.time.Duration

/**
 * Represents an SSL/TLS connection in the domain.
 */
data class SSLConnection(
    val host: String,
    val port: Int,
    val protocol: String,
    val cipherSuite: String,
    val handshakeTime: Duration,
    val isSecure: Boolean,
    val certificateChain: List<X509Certificate> = emptyList()
) 