package org.example.ssl

import java.security.cert.X509Certificate

/**
 * Represents the result of an SSL/TLS connection test.
 *
 * @property success Whether the connection was successful
 * @property certificateChain The chain of certificates presented by the server
 * @property error Any error that occurred during the connection
 * @property cipherSuite The negotiated cipher suite
 * @property httpStatus The HTTP status code received
 * @property hostnameVerified Whether the hostname verification passed
 */
data class SSLConnectionResult(
    val success: Boolean,
    val certificateChain: List<X509Certificate>,
    val error: Exception?,
    val cipherSuite: String,
    val httpStatus: Int,
    val hostnameVerified: Boolean
) {
    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("→ HTTP Status  : $httpStatus\n")
        sb.append("→ Cipher Suite : $cipherSuite\n")
        sb.append("→ Certificate chain ${if (success) "trusted" else "not trusted"}\n")
        sb.append("→ Hostname verification ${if (hostnameVerified) "passed" else "failed"}\n")
        
        if (certificateChain.isNotEmpty()) {
            sb.append("→ Server sent ${certificateChain.size} certificate(s):\n")
            certificateChain.forEachIndexed { index, cert ->
                sb.append("\nCertificate [${index + 1}]\n")
                sb.append("    Subject DN    : ${cert.subjectX500Principal.name}\n")
                sb.append("    Issuer DN     : ${cert.issuerX500Principal.name}\n")
                sb.append("    Version       : ${cert.version}\n")
                sb.append("    Serial Number : ${cert.serialNumber.toString(16).uppercase()}\n")
                sb.append("    Valid From    : ${cert.notBefore}\n")
                sb.append("    Valid Until   : ${cert.notAfter}\n")
                sb.append("    Sig. Algorithm: ${cert.sigAlgName}\n")
                sb.append("    PubKey Alg    : ${cert.publicKey.algorithm}")
                
                // Add Subject Alternative Names extension information
                try {
                    cert.subjectAlternativeNames?.let { sans ->
                        if (sans.isNotEmpty()) {
                            sb.append("\n    Subject Alternative Names:\n")
                            sans.forEach { san ->
                                val type = san[0] as Int
                                val value = san[1] as String
                                sb.append("        Type $type: $value\n")
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Ignore if SAN cannot be retrieved
                }
            }
        }
        
        return sb.toString()
    }
} 