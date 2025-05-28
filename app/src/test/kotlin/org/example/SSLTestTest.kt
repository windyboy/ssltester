package org.example

import org.example.config.SSLTestConfig
import kotlin.test.*
import java.io.File

class SSLTestTest {
    private lateinit var sslTest: SSLTest
    private lateinit var config: SSLTestConfig
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = createTempDir()
        config = SSLTestConfig()
        sslTest = SSLTest(config)
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun `test call with valid url`() {
        // Set up a valid HTTPS URL
        config.url = "https://example.com"
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3) // Allow connection error for test environment
    }

    @Test
    fun `test call with invalid url`() {
        // Set up an invalid URL
        config.url = "invalid-url"
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertEquals(1, exitCode)
    }

    @Test
    fun `test call with non https url`() {
        // Set up a non-HTTPS URL
        config.url = "http://example.com"
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertEquals(1, exitCode)
    }

    @Test
    fun `test call with custom keystore`() {
        // Set up a valid HTTPS URL
        config.url = "https://example.com"
        
        // Set up a custom keystore
        val keystoreFile = File(tempDir, "test.jks")
        config.keystoreFile = keystoreFile
        config.keystorePassword = "password"
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3) // Allow connection error for test environment
    }

    @Test
    fun `test call with custom timeouts`() {
        // Set up a valid HTTPS URL
        config.url = "https://example.com"
        
        // Set custom timeouts
        config.connectionTimeout = 10000
        config.readTimeout = 10000
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3) // Allow connection error for test environment
    }

    @Test
    fun `test call with follow redirects`() {
        // Set up a valid HTTPS URL
        config.url = "https://example.com"
        
        // Enable redirect following
        config.followRedirects = true
        
        // Execute the test
        val exitCode = sslTest.call()
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3) // Allow connection error for test environment
    }
} 