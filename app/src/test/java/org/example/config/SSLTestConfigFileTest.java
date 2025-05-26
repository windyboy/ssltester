package org.example.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SSLTestConfigFileTest {
    private File yamlConfigFile;
    private File jsonConfigFile;
    private File invalidConfigFile;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws IOException {
        // 创建YAML配置文件
        yamlConfigFile = new File(tempDir, "config.yaml");
        try (FileWriter writer = new FileWriter(yamlConfigFile)) {
            writer.write("connectionTimeout: 10000\n");
            writer.write("readTimeout: 10000\n");
            writer.write("followRedirects: true\n");
            writer.write("verbose: true\n");
            writer.write("format: YAML\n");
        }

        // 创建JSON配置文件
        jsonConfigFile = new File(tempDir, "config.json");
        try (FileWriter writer = new FileWriter(jsonConfigFile)) {
            writer.write("{\n");
            writer.write("  \"connectionTimeout\": 10000,\n");
            writer.write("  \"readTimeout\": 10000,\n");
            writer.write("  \"followRedirects\": true,\n");
            writer.write("  \"verbose\": true,\n");
            writer.write("  \"format\": \"JSON\"\n");
            writer.write("}\n");
        }

        // 创建无效的配置文件
        invalidConfigFile = new File(tempDir, "config.txt");
        try (FileWriter writer = new FileWriter(invalidConfigFile)) {
            writer.write("invalid content");
        }
    }

    @Test
    void testLoadYAMLConfig() throws IOException {
        Map<String, Object> config = SSLTestConfigFile.loadConfig(yamlConfigFile);
        
        assertNotNull(config);
        assertEquals(10000, config.get("connectionTimeout"));
        assertEquals(10000, config.get("readTimeout"));
        assertEquals(true, config.get("followRedirects"));
        assertEquals(true, config.get("verbose"));
        assertEquals("YAML", config.get("format"));
    }

    @Test
    void testLoadJSONConfig() throws IOException {
        Map<String, Object> config = SSLTestConfigFile.loadConfig(jsonConfigFile);
        
        assertNotNull(config);
        assertEquals(10000, config.get("connectionTimeout"));
        assertEquals(10000, config.get("readTimeout"));
        assertEquals(true, config.get("followRedirects"));
        assertEquals(true, config.get("verbose"));
        assertEquals("JSON", config.get("format"));
    }

    @Test
    void testLoadConfig_WithNonExistentFile() {
        File nonExistentFile = new File(tempDir, "nonexistent.yaml");
        assertThrows(IOException.class, () -> SSLTestConfigFile.loadConfig(nonExistentFile));
    }

    @Test
    void testLoadConfig_WithInvalidFormat() {
        assertThrows(IOException.class, () -> SSLTestConfigFile.loadConfig(invalidConfigFile));
    }

    @Test
    void testApplyConfig() throws IOException {
        Map<String, Object> config = SSLTestConfigFile.loadConfig(yamlConfigFile);
        SSLTestConfig sslConfig = new SSLTestConfig();
        
        SSLTestConfigFile.applyConfig(config, sslConfig);
        
        assertEquals(10000, sslConfig.getConnectionTimeout());
        assertEquals(10000, sslConfig.getReadTimeout());
        assertTrue(sslConfig.isFollowRedirects());
        assertTrue(sslConfig.isVerbose());
        assertEquals(SSLTestConfig.OutputFormat.YAML, sslConfig.getFormat());
    }

    @Test
    void testApplyConfig_WithNullConfig() {
        SSLTestConfig sslConfig = new SSLTestConfig();
        SSLTestConfigFile.applyConfig(null, sslConfig);
        // 不应该抛出异常，应该保持默认值
    }

    @Test
    void testApplyConfig_WithInvalidValues() throws IOException {
        // 创建包含无效值的配置文件
        File invalidValuesFile = new File(tempDir, "invalid_values.yaml");
        try (FileWriter writer = new FileWriter(invalidValuesFile)) {
            writer.write("connectionTimeout: invalid\n");
            writer.write("readTimeout: invalid\n");
            writer.write("followRedirects: invalid\n");
        }

        Map<String, Object> config = SSLTestConfigFile.loadConfig(invalidValuesFile);
        SSLTestConfig sslConfig = new SSLTestConfig();
        
        // 应用配置不应该抛出异常，应该保持默认值
        SSLTestConfigFile.applyConfig(config, sslConfig);
        
        // 验证默认值保持不变
        assertEquals(5000, sslConfig.getConnectionTimeout());
        assertEquals(5000, sslConfig.getReadTimeout());
        assertFalse(sslConfig.isFollowRedirects());
    }
} 