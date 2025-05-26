package org.example.output;

import org.example.config.SSLTestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResultFormatterTest {
    private ResultFormatter formatter;
    private SSLTestConfig config;
    private Map<String, Object> testResult;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() {
        config = new SSLTestConfig();
        formatter = new ResultFormatter(config);
        testResult = new HashMap<>();
        testResult.put("status", "success");
        testResult.put("httpStatus", 200);
        testResult.put("cipherSuite", "TLS_AES_128_GCM_SHA256");
    }

    @Test
    void testFormatAndOutput_TextFormat() {
        config.setFormat(SSLTestConfig.OutputFormat.TEXT);
        formatter.formatAndOutput(testResult);
        // Note: Since this is output formatting, we mainly test that it doesn't throw exceptions
    }

    @Test
    void testFormatAndOutput_JsonFormat() {
        config.setFormat(SSLTestConfig.OutputFormat.JSON);
        formatter.formatAndOutput(testResult);
        // Note: Since this is output formatting, we mainly test that it doesn't throw exceptions
    }

    @Test
    void testFormatAndOutput_YamlFormat() {
        config.setFormat(SSLTestConfig.OutputFormat.YAML);
        formatter.formatAndOutput(testResult);
        // Note: Since this is output formatting, we mainly test that it doesn't throw exceptions
    }

    @Test
    void testFormatAndOutput_WithOutputFile() throws Exception {
        File outputFile = new File(tempDir, "output.txt");
        config.setOutputFile(outputFile);
        config.setFormat(SSLTestConfig.OutputFormat.TEXT);
        
        formatter.formatAndOutput(testResult);
        
        assertTrue(outputFile.exists());
        String content = Files.readString(outputFile.toPath());
        assertTrue(content.contains("success"));
        assertTrue(content.contains("200"));
        assertTrue(content.contains("TLS_AES_128_GCM_SHA256"));
    }

    @Test
    void testLogError() {
        String errorMessage = "Test error message";
        Throwable cause = new RuntimeException("Test cause");
        int exitCode = 1;
        
        formatter.logError(errorMessage, cause, exitCode);
        // Note: Since this is logging, we mainly test that it doesn't throw exceptions
    }

    @Test
    void testFormatAndOutput_WithError() {
        testResult.put("error", "Test error");
        testResult.put("errorCause", "Test cause");
        testResult.put("exitCode", 1);
        
        formatter.formatAndOutput(testResult);
        // Note: Since this is output formatting, we mainly test that it doesn't throw exceptions
    }
} 