package org.example.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SecurityStrengthAnalyzerTest {
    @Test
    fun `protocol strong`() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.3"))
    }

    @Test
    fun `protocol weak`() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeProtocol("SSLv3"))
    }

    @Test
    fun `protocol adequate`() {
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeProtocol("TLSv1.4"))
    }

    @Test
    fun `protocol unknown`() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeProtocol(null))
    }

    @Test
    fun `cipher strong`() {
        assertEquals("STRONG", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_AES_128_GCM_SHA256"))
    }

    @Test
    fun `cipher weak`() {
        assertEquals("WEAK", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_RSA_WITH_RC4_128_MD5"))
    }

    @Test
    fun `cipher adequate`() {
        assertEquals("ADEQUATE", SecurityStrengthAnalyzer.analyzeCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"))
    }

    @Test
    fun `cipher unknown`() {
        assertEquals("UNKNOWN", SecurityStrengthAnalyzer.analyzeCipherSuite(null))
    }
}
