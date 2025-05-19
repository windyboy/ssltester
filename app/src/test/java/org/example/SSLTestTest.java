package org.example;

import org.example.config.SSLTestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class SSLTestTest {
    private SSLTest sslTest;
    private SSLTestConfig config;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() {
        config = new SSLTestConfig();
        sslTest = new SSLTest(config);
    }

    @Test
    void testCall_WithValidUrl() {
        // Set up a valid HTTPS URL
        config.setUrl("https://example.com");
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3); // Allow connection error for test environment
    }

    @Test
    void testCall_WithInvalidUrl() {
        // Set up an invalid URL
        config.setUrl("invalid-url");
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertEquals(1, exitCode);
    }

    @Test
    void testCall_WithNonHttpsUrl() {
        // Set up a non-HTTPS URL
        config.setUrl("http://example.com");
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertEquals(1, exitCode);
    }

    @Test
    void testCall_WithCustomKeystore() {
        // Set up a valid HTTPS URL
        config.setUrl("https://example.com");
        
        // Set up a custom keystore
        File keystoreFile = new File(tempDir, "test.jks");
        config.setKeystoreFile(keystoreFile);
        config.setKeystorePassword("password");
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3); // Allow connection error for test environment
    }

    @Test
    void testCall_WithCustomTimeouts() {
        // Set up a valid HTTPS URL
        config.setUrl("https://example.com");
        
        // Set custom timeouts
        config.setConnectionTimeout(10000);
        config.setReadTimeout(10000);
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3); // Allow connection error for test environment
    }

    @Test
    void testCall_WithFollowRedirects() {
        // Set up a valid HTTPS URL
        config.setUrl("https://example.com");
        
        // Enable redirect following
        config.setFollowRedirects(true);
        
        // Execute the test
        int exitCode = sslTest.call();
        
        // Verify the result
        assertTrue(exitCode == 0 || exitCode == 3); // Allow connection error for test environment
    }
} 