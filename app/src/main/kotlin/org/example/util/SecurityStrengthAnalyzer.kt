package org.example.util

/**
 * Utility class designed to assess the security level of TLS/SSL protocols and cipher suites.
 * It bases its analysis on current best practices and known vulnerabilities, using a
 * keyword-based approach for classification.
 */
object SecurityStrengthAnalyzer {
    /** Represents a strong security level. */
    const val STRENGTH_STRONG = "STRONG"
    /** Represents an adequate security level, not ideal but acceptable. */
    const val STRENGTH_ADEQUATE = "ADEQUATE"
    /** Represents a weak security level, potentially vulnerable. */
    const val STRENGTH_WEAK = "WEAK"
    /** Represents an unknown security level, typically due to missing or unrecognized input. */
    const val STRENGTH_UNKNOWN = "UNKNOWN"

    /** List of keywords identifying known weak protocols. Case-insensitive matching is performed. */
    private val WEAK_PROTOCOLS = listOf("SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1")
    /** List of keywords identifying known strong protocols. Case-insensitive matching is performed. */
    private val STRONG_PROTOCOLS = listOf("TLSV1.2", "TLSV1.3")

    /** List of keywords identifying known weak components in cipher suites. Case-insensitive matching is performed. */
    private val WEAK_CIPHER_KEYWORDS = listOf(
        "_NULL_", "_ANON_", "_EXPORT_", "_DES_", "_3DES_EDE_CBC_", "RC4_", "_MD5"
    )
    /** List of keywords identifying known strong components in cipher suites. Case-insensitive matching is performed. */
    private val STRONG_CIPHER_KEYWORDS = listOf(
        "_AES_128_GCM_", "_AES_256_GCM_", "_CHACHA20_POLY1305_"
    )

    /**
     * Analyzes the given TLS/SSL protocol string and classifies its strength.
     *
     * @param protocolVersion The protocol version string to analyze (e.g., "TLSv1.2", "SSLv3").
     * @return A string constant representing the strength:
     *         [STRENGTH_STRONG] for protocols like TLSv1.2, TLSv1.3.
     *         [STRENGTH_WEAK] for protocols like SSLv3, TLSv1.0, TLSv1.1.
     *         [STRENGTH_ADEQUATE] for unrecognized but not explicitly weak protocols (e.g., future versions).
     *         [STRENGTH_UNKNOWN] if the input is null or empty.
     */
    fun analyzeProtocol(protocol: String?): String {
        if (protocol == null || protocol.isEmpty()) {
            return "UNKNOWN"
        }

        val normalizedProtocol = protocol.uppercase()
        return when {
            normalizedProtocol.contains("TLSV1.3") -> "STRONG"
            normalizedProtocol.contains("TLSV1.2") -> "STRONG"
            normalizedProtocol.contains("TLSV1.1") -> "WEAK"
            normalizedProtocol.contains("TLSV1.0") -> "WEAK"
            normalizedProtocol.contains("TLSV1") -> "WEAK" // Alias
            normalizedProtocol.contains("SSLV3") -> "WEAK"
            normalizedProtocol.contains("SSL") -> "WEAK" // General SSL
            normalizedProtocol.contains("SSLV2") -> "WEAK"
            normalizedProtocol.contains("TLSV1.4") -> "ADEQUATE"
            normalizedProtocol.contains("TLSV2.0") -> "ADEQUATE"
            else -> "UNKNOWN"
        }
    }

    /**
     * Analyzes the given cipher suite string and classifies its strength.
     * The classification is based on keywords indicating known weak mechanisms (e.g., NULL, ANON, EXPORT, RC4, DES, MD5)
     * or strong mechanisms (e.g., GCM, CHACHA20_POLY1305). Cipher suites not matching these specific
     * weak or strong indicators are generally considered ADEQUATE, especially if they involve AES.
     *
     * @param cipherSuite The cipher suite string to analyze (e.g., "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
     * @return A string constant representing the strength:
     *         [STRENGTH_STRONG] for ciphers with strong components like AES_GCM or CHACHA20_POLY1305.
     *         [STRENGTH_WEAK] for ciphers with known weak components like NULL, ANON, EXPORT, RC4, DES, MD5.
     *         [STRENGTH_ADEQUATE] for ciphers that are not identified as explicitly strong or weak.
     *         [STRENGTH_UNKNOWN] if the input is null or empty.
     */
    fun analyzeCipherSuite(cipherSuite: String?): String {
        if (cipherSuite == null || cipherSuite.isEmpty()) {
            return "UNKNOWN"
        }

        val normalizedCipher = cipherSuite.uppercase()
        return when {
            // Strong ciphers
            normalizedCipher.contains("_GCM_") -> "STRONG"
            normalizedCipher.contains("_POLY1305_") -> "STRONG"
            normalizedCipher.contains("CHACHA20") -> "STRONG"
            
            // Weak ciphers
            normalizedCipher.contains("_NULL_") -> "WEAK"
            normalizedCipher.contains("_ANON_") -> "WEAK"
            normalizedCipher.contains("_EXPORT_") -> "WEAK"
            normalizedCipher.contains("_DES_") -> "WEAK"
            normalizedCipher.contains("_RC4_") -> "WEAK"
            normalizedCipher.contains("_IDEA_") -> "WEAK"
            normalizedCipher.contains("_MD5") -> "WEAK"
            normalizedCipher.contains("_3DES_") -> "WEAK"
            
            // Adequate ciphers
            normalizedCipher.contains("_AES_") -> "ADEQUATE"
            normalizedCipher.contains("_SHA") -> "ADEQUATE"
            
            else -> "UNKNOWN"
        }
    }
} 