package org.example.cert

import kotlin.test.*
import java.net.IDN

class IDNTest {
    @Test
    fun `test IDN conversion`() {
        // Test Russian domain
        val russianDomain = "пример.рф"
        val punycode = IDN.toASCII(russianDomain)
        val unicode = IDN.toUnicode(punycode)
        
        assertEquals("xn--e1afmkfd.xn--p1ai", punycode)
        assertEquals(russianDomain, unicode)
    }

    @Test
    fun `test IDN with mixed characters`() {
        // Test domain with mixed ASCII and non-ASCII characters
        val mixedDomain = "test-пример.com"
        val punycode = IDN.toASCII(mixedDomain)
        val unicode = IDN.toUnicode(punycode)
        
        assertEquals("test--e1afmkfd.com", punycode)
        assertEquals(mixedDomain, unicode)
    }

    @Test
    fun `test IDN with multiple labels`() {
        // Test domain with multiple labels
        val multiLabelDomain = "sub.пример.рф"
        val punycode = IDN.toASCII(multiLabelDomain)
        val unicode = IDN.toUnicode(punycode)
        
        assertEquals("sub.xn--e1afmkfd.xn--p1ai", punycode)
        assertEquals(multiLabelDomain, unicode)
    }
} 