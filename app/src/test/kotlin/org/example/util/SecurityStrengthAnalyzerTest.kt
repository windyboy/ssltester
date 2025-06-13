package org.example.util

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class SecurityStrengthAnalyzerTest {
    @Test
    fun `protocol analysis returns expected strength`() {
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_STRONG, SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.3"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_WEAK, SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.0"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_ADEQUATE, SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.4"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_UNKNOWN, SecurityStrengthAnalyzer.analyzeProtocol(null))
    }

    @Test
    fun `cipher suite analysis returns expected strength`() {
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_STRONG, SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_WEAK, SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_RC4_128_MD5"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_ADEQUATE, SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_AES_256_CBC_SHA"))
        assertEquals(SecurityStrengthAnalyzer.STRENGTH_UNKNOWN, SecurityStrengthAnalyzer.analyzeCipherSuite(null))
    }
}
