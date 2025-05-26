package org.example.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SecurityStrengthAnalyzerTest {

    // Protocol Strength Tests
    @Test
    void testAnalyzeProtocol_TLS13_Strong() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.3"));
    }

    @Test
    void testAnalyzeProtocol_TLS12_Strong() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.2"));
    }

    @Test
    void testAnalyzeProtocol_TLS11_Weak() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.1"));
    }

    @Test
    void testAnalyzeProtocol_TLS10_Weak() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.0"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("TLSV1")); // Alias
    }

    @Test
    void testAnalyzeProtocol_SSLv3_Weak() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("SSLv3"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("SSL")); // General SSL
    }
    
    @Test
    void testAnalyzeProtocol_SSLv2_Weak() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("SSLv2"));
    }


    @Test
    void testAnalyzeProtocol_Empty_Unknown() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeProtocol(""));
    }

    @Test
    void testAnalyzeProtocol_Null_Unknown() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeProtocol(null));
    }

    @Test
    void testAnalyzeProtocol_FutureVersion_Adequate() {
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeProtocol("TLSV1.4"));
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeProtocol("TLSv2.0"));
    }
    
    @Test
    void testAnalyzeProtocol_MixedCase_CorrectEvaluation() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeProtocol("TlSv1.3"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("sslv3"));
    }

    // Cipher Suite Strength Tests
    @Test
    void testAnalyzeCipherSuite_StrongGCM() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"));
    }

    @Test
    void testAnalyzeCipherSuite_StrongChaCha20() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"));
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_CHACHA20_POLY1305_SHA256")); // Older form
    }

    @Test
    void testAnalyzeCipherSuite_WeakNull() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_NULL_SHA256"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_RSA_WITH_NULL_MD5"));
    }

    @Test
    void testAnalyzeCipherSuite_WeakAnon() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"));
    }

    @Test
    void testAnalyzeCipherSuite_WeakExport() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_EXPORT_WITH_RC4_40_MD5"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA"));
    }

    @Test
    void testAnalyzeCipherSuite_WeakDES() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_DES_CBC_SHA"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_DHE_DSS_WITH_DES_CBC_SHA"));
    }

    @Test
    void testAnalyzeCipherSuite_WeakRC4() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_RC4_128_SHA"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_RSA_WITH_RC4_128_MD5"));
    }

    @Test
    void testAnalyzeCipherSuite_WeakMD5() {
        // Testing MD5 in the context of a MAC or PRF, implied by its presence in legacy ciphers
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_IDEA_CBC_MD5"));
        // Also testing if _MD5 appears anywhere else, as per WEAK_CIPHER_KEYWORDS
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SOME_CIPHER_SUITE_MD5_XYZ"));
    }

    @Test
    void testAnalyzeCipherSuite_Weak3DES() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA"));
    }

    @Test
    void testAnalyzeCipherSuite_AdequateModernCBC() {
        // AES_CBC with strong SHA for HMAC
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"));
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_DHE_RSA_WITH_AES_256_CBC_SHA384"));
    }

    @Test
    void testAnalyzeCipherSuite_AdequateSimpleAES() {
        // AES_CBC with older SHA1 for HMAC - considered adequate but less than ideal
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA"));
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA"));
    }

    @Test
    void testAnalyzeCipherSuite_Empty_Unknown() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeCipherSuite(""));
    }

    @Test
    void testAnalyzeCipherSuite_Null_Unknown() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeCipherSuite(null));
    }
    
    @Test
    void testAnalyzeCipherSuite_MixedCase_CorrectEvaluation() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("tls_ecdhe_rsa_with_aes_256_gcm_sha384"));
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("Tls_Rsa_With_Des_Cbc_Sha"));
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("tls_rsa_with_aes_128_cbc_sha"));
    }

    @Test
    void testAnalyzeCipherSuite_UnrecognizedButNotWeak_Adequate() {
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_SOME_NEW_CIPHER_WITH_AES_SHA512"));
    }
}
