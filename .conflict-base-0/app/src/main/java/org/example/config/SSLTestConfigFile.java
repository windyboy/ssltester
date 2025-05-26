package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SSLTestConfigFile {
    private static final Logger logger = LoggerFactory.getLogger(SSLTestConfigFile.class);
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadConfig(File configFile) throws IOException {
        if (!configFile.exists()) {
            throw new IOException("Configuration file does not exist: " + configFile);
        }

        String fileName = configFile.getName().toLowerCase();
        if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
            return (Map<String, Object>) YAML_MAPPER.readValue(configFile, HashMap.class);
        } else if (fileName.endsWith(".json")) {
            return (Map<String, Object>) JSON_MAPPER.readValue(configFile, HashMap.class);
        } else {
            throw new IOException("Unsupported configuration file format. Use .yaml, .yml, or .json");
        }
    }

    public static void applyConfig(Map<String, Object> config, SSLTestConfig sslConfig) {
        if (config == null) {
            return;
        }

        try {
            // Apply configuration values
            if (config.containsKey("connectionTimeout")) {
                sslConfig.setConnectionTimeout(Integer.parseInt(config.get("connectionTimeout").toString()));
            }
            if (config.containsKey("readTimeout")) {
                sslConfig.setReadTimeout(Integer.parseInt(config.get("readTimeout").toString()));
            }
            if (config.containsKey("followRedirects")) {
                sslConfig.setFollowRedirects(Boolean.parseBoolean(config.get("followRedirects").toString()));
            }
            if (config.containsKey("keystoreFile")) {
                sslConfig.setKeystoreFile(new File(config.get("keystoreFile").toString()));
            }
            if (config.containsKey("keystorePassword")) {
                sslConfig.setKeystorePassword(config.get("keystorePassword").toString());
            }
            if (config.containsKey("outputFile")) {
                sslConfig.setOutputFile(new File(config.get("outputFile").toString()));
            }
            if (config.containsKey("format")) {
                sslConfig.setFormat(SSLTestConfig.OutputFormat.valueOf(config.get("format").toString().toUpperCase()));
            }
            if (config.containsKey("verbose")) {
                sslConfig.setVerbose(Boolean.parseBoolean(config.get("verbose").toString()));
            }
        } catch (Exception e) {
            logger.warn("Error applying configuration: {}", e.getMessage());
        }
    }
} 