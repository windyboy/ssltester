package org.example.util;

import java.util.Arrays;
import java.util.List;

/**
 * Utility class designed to assess the security level of TLS/SSL protocols and cipher suites.
 * It bases its analysis on current best practices and known vulnerabilities, using a
 * keyword-based approach for classification.
 */
public class SecurityStrengthAnalyzer {

    /** Represents a strong security level. */
    public static final String STRENGTH_STRONG = "STRONG";
    /** Represents an adequate security level, not ideal but acceptable. */
    public static final String STRENGTH_ADEQUATE = "ADEQUATE";
    /** Represents a weak security level, potentially vulnerable. */
    public static final String STRENGTH_WEAK = "WEAK";
    /** Represents an unknown security level, typically due to missing or unrecognized input. */
    public static final String STRENGTH_UNKNOWN = "UNKNOWN";

    /** List of keywords identifying known weak protocols. Case-insensitive matching is performed. */
    private static final List<String> WEAK_PROTOCOLS = Arrays.asList("SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1");
    /** List of keywords identifying known strong protocols. Case-insensitive matching is performed. */
    private static final List<String> STRONG_PROTOCOLS = Arrays.asList("TLSV1.2", "TLSV1.3");

    /** List of keywords identifying known weak components in cipher suites. Case-insensitive matching is performed. */
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList(
        "_NULL_", "_ANON_", "_EXPORT_", "_DES_", "_3DES_EDE_CBC_", "RC4_", "_MD5"
    );
    /** List of keywords identifying known strong components in cipher suites. Case-insensitive matching is performed. */
    private static final List<String> STRONG_CIPHER_KEYWORDS = Arrays.asList(
        "_AES_128_GCM_", "_AES_256_GCM_", "_CHACHA20_POLY1305_"
    );

    /**
     * Analyzes the given TLS/SSL protocol string and classifies its strength.
     *
     * @param protocolVersion The protocol version string to analyze (e.g., "TLSv1.2", "SSLv3").
     * @return A string constant representing the strength:
     *         {@link #STRENGTH_STRONG} for protocols like TLSv1.2, TLSv1.3.
     *         {@link #STRENGTH_WEAK} for protocols like SSLv3, TLSv1.0, TLSv1.1.
     *         {@link #STRENGTH_ADEQUATE} for unrecognized but not explicitly weak protocols (e.g., future versions).
     *         {@link #STRENGTH_UNKNOWN} if the input is null or empty.
     */
    public static String analyzeProtocol(String protocolVersion) {
        if (protocolVersion == null || protocolVersion.isEmpty()) {
            return STRENGTH_UNKNOWN;
        }

        // Normalize the protocol version for comparison
        String normalizedProtocol = protocolVersion.toUpperCase().replaceAll("\\s+", "");
        
        // Check for strong protocols
        for (String strong : STRONG_PROTOCOLS) {
            if (normalizedProtocol.equals(strong) || 
                normalizedProtocol.equals(strong.replace("V", ""))) {
                return STRENGTH_STRONG;
            }
        }
        
        // Check for weak protocols
        for (String weak : WEAK_PROTOCOLS) {
            if (normalizedProtocol.equals(weak) || 
                normalizedProtocol.equals(weak.replace("V", "")) || // Handle TLS1.0 vs TLSV1.0
                (weak.equals("SSL") && normalizedProtocol.startsWith("SSL"))) {
                return STRENGTH_WEAK;
            }
        }

        // Check for future TLS versions (e.g., TLSv1.4, TLSv2.0, TLS1.4, TLS2.0)
        if (normalizedProtocol.matches("TLS[V]?[0-9]+(\\.[0-9]+)?")) {
            // Extract version number to determine if it's future
            String versionPart = normalizedProtocol.replaceAll("TLS[V]?", "");
            if (versionPart.matches("[2-9]\\.[0-9]+") || // TLS 2.x and above
                versionPart.matches("1\\.[4-9]") ||      // TLS 1.4 and above
                versionPart.matches("[2-9]")) {          // TLS 2 and above
                return STRENGTH_ADEQUATE;
            }
        }

        return STRENGTH_UNKNOWN;
    }

    /**
     * Analyzes the given cipher suite string and classifies its strength.
     * The classification is based on keywords indicating known weak mechanisms (e.g., NULL, ANON, EXPORT, RC4, DES, MD5)
     * or strong mechanisms (e.g., GCM, CHACHA20_POLY1305). Cipher suites not matching these specific
     * weak or strong indicators are generally considered ADEQUATE, especially if they involve AES.
     *
     * @param cipherSuite The cipher suite string to analyze (e.g., "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
     * @return A string constant representing the strength:
     *         {@link #STRENGTH_STRONG} for ciphers with strong components like AES_GCM or CHACHA20_POLY1305.
     *         {@link #STRENGTH_WEAK} for ciphers with known weak components like NULL, ANON, EXPORT, RC4, DES, MD5.
     *         {@link #STRENGTH_ADEQUATE} for ciphers that are not identified as explicitly strong or weak.
     *         {@link #STRENGTH_UNKNOWN} if the input is null or empty.
     */
    public static String analyzeCipherSuite(String cipherSuite) {
        if (cipherSuite == null || cipherSuite.isEmpty()) {
            return STRENGTH_UNKNOWN;
        }
        String upperCipher = cipherSuite.toUpperCase();

        for (String weakKeyword : WEAK_CIPHER_KEYWORDS) {
            if (upperCipher.contains(weakKeyword)) {
                return STRENGTH_WEAK;
            }
        }

        for (String strongKeyword : STRONG_CIPHER_KEYWORDS) {
            if (upperCipher.contains(strongKeyword)) {
                return STRENGTH_STRONG;
            }
        }
        
        if (upperCipher.contains("_AES_")) {
             if (upperCipher.contains("_CBC_") && (upperCipher.contains("_SHA256") || upperCipher.contains("_SHA384"))) {
                return STRENGTH_ADEQUATE; // Modern CBC modes are okay, but not as good as GCM
             }
             // Other AES without GCM or strong CBC might be adequate but lean towards caution
        }

        return STRENGTH_ADEQUATE; // Default for ciphers not caught by specific weak/strong keywords
    }
}
