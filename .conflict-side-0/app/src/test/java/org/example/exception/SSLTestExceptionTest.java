package org.example.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SSLTestExceptionTest {
    @Test
    void testConstructor_WithMessage() {
        String message = "Test error message";
        int exitCode = 1;
        
        SSLTestException exception = new SSLTestException(message, exitCode);
        
        assertEquals(message, exception.getMessage());
        assertEquals(exitCode, exception.getExitCode());
        assertNull(exception.getCause());
    }

    @Test
    void testConstructor_WithMessageAndCause() {
        String message = "Test error message";
        Throwable cause = new RuntimeException("Test cause");
        int exitCode = 1;
        
        SSLTestException exception = new SSLTestException(message, exitCode, cause);
        
        assertEquals(message, exception.getMessage());
        assertEquals(exitCode, exception.getExitCode());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void testGetExitCode() {
        int exitCode = 2;
        SSLTestException exception = new SSLTestException("Test", exitCode);
        
        assertEquals(exitCode, exception.getExitCode());
    }
} 