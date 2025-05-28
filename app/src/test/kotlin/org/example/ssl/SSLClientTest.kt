package org.example.ssl

import kotlin.test.*
import java.io.File
import java.net.URL
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

class SSLClientTest {
    private lateinit var sslClient: SSLClient
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = createTempDir()
        sslClient = SSLClient(
            connectTimeout = 5000,
            readTimeout = 5000,
            followRedirects = true
        )
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun `test connect to valid HTTPS URL`() {
        val url = URL("https://example.com")
        val result = sslClient.connect(url)
        
        assertTrue(result.success)
        assertNotNull(result.certificateChain)
        assertTrue(result.hostnameVerified)
    }

    @Test
    fun `test connect to invalid HTTPS URL`() {
        val url = URL("https://invalid.example.com")
        val result = sslClient.connect(url)
        
        assertFalse(result.success)
        assertNotNull(result.error)
    }

    @Test
    fun `test connect to non-HTTPS URL`() {
        val url = URL("http://example.com")
        
        assertFailsWith<IllegalArgumentException> {
            sslClient.connect(url)
        }
    }

    @Test
    fun `test connect with custom SSL socket factory`() {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, null, null)
        val sslSocketFactory = sslContext.socketFactory
        
        val client = SSLClient(
            connectTimeout = 5000,
            readTimeout = 5000,
            followRedirects = true,
            sslSocketFactory = sslSocketFactory
        )
        
        val url = URL("https://example.com")
        val result = client.connect(url)
        
        assertTrue(result.success)
    }

    @Test
    fun `test close connection`() {
        val url = URL("https://example.com")
        sslClient.connect(url)
        sslClient.close()
        
        // No exception should be thrown
    }
} 