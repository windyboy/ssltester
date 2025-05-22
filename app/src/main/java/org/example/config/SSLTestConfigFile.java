package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for loading and applying configuration settings from YAML or JSON files
 * to an {@link SSLTestConfig} object.
 */
public class SSLTestConfigFile {
    private static final Logger logger = LoggerFactory.getLogger(SSLTestConfigFile.class);
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    /**
     * Loads configuration settings from the specified YAML or JSON file.
     * The file type is determined by its extension (.yaml, .yml, or .json).
     *
     * @param configFile The configuration file to load. Must not be null.
     * @return A map containing the configuration key-value pairs.
     * @throws IOException If the file does not exist, is unsupported, or cannot be read/parsed.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadConfig(File configFile) throws IOException {
        if (configFile == null) {
            throw new IOException("Configuration file cannot be null.");
        }
        if (!configFile.exists()) {
            throw new IOException("Configuration file does not exist: " + configFile.getAbsolutePath());
        }

        String fileName = configFile.getName().toLowerCase();
        logger.info("Attempting to load configuration from: {}", configFile.getAbsolutePath());

        if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
            logger.debug("Parsing as YAML file.");
            return (Map<String, Object>) YAML_MAPPER.readValue(configFile, HashMap.class);
        } else if (fileName.endsWith(".json")) {
            logger.debug("Parsing as JSON file.");
            return (Map<String, Object>) JSON_MAPPER.readValue(configFile, HashMap.class);
        } else {
            logger.error("Unsupported configuration file format for: {}. Only .yaml, .yml, or .json are supported.", configFile.getAbsolutePath());
            throw new IOException("Unsupported configuration file format. Use .yaml, .yml, or .json");
        }
    }

    /**
     * Applies the loaded configuration values from a map to an {@link SSLTestConfig} object.
     * This method attempts to parse and set various configuration options.
     * It logs a warning if any specific configuration value cannot be applied.
     *
     * @param fileConfigMap The map of configuration values (typically loaded from a file).
     *                      If null, the method returns without making changes.
     * @param targetSslConfig The {@link SSLTestConfig} object to update with the loaded values. Must not be null.
     */
    public static void applyConfig(Map<String, Object> fileConfigMap, SSLTestConfig targetSslConfig) {
        if (fileConfigMap == null) {
            logger.debug("Input configuration map is null, no settings to apply.");
            return;
        }
        if (targetSslConfig == null) {
            logger.warn("Target SSLTestConfig is null, cannot apply settings.");
            return;
        }

        logger.info("Applying loaded configuration to SSLTestConfig object.");

        // Helper to safely apply a configuration value
        applyString(fileConfigMap, "url", targetSslConfig::setUrl);
        applyInt(fileConfigMap, "connectionTimeout", targetSslConfig::setConnectionTimeout);
        applyInt(fileConfigMap, "readTimeout", targetSslConfig::setReadTimeout);
        applyBoolean(fileConfigMap, "followRedirects", targetSslConfig::setFollowRedirects);
        applyFile(fileConfigMap, "keystoreFile", targetSslConfig::setKeystoreFile);
        applyString(fileConfigMap, "keystorePassword", targetSslConfig::setKeystorePassword);
        applyFile(fileConfigMap, "clientCertFile", targetSslConfig::setClientCertFile);
        applyFile(fileConfigMap, "clientKeyFile", targetSslConfig::setClientKeyFile);
        applyString(fileConfigMap, "clientKeyPassword", targetSslConfig::setClientKeyPassword);
        applyEnum(fileConfigMap, "clientCertFormat", SSLTestConfig.CertificateFormat.class, targetSslConfig::setClientCertFormat);
        applyFile(fileConfigMap, "outputFile", targetSslConfig::setOutputFile);
        applyEnum(fileConfigMap, "format", SSLTestConfig.OutputFormat.class, targetSslConfig::setFormat);
        applyBoolean(fileConfigMap, "verbose", targetSslConfig::setVerbose);
        applyBoolean(fileConfigMap, "logCertDetails", targetSslConfig::setLogCertDetails);
        // configFile itself is not set via this method, as it's a meta-parameter.
        applyBoolean(fileConfigMap, "checkOCSP", targetSslConfig::setCheckOCSP);
        applyBoolean(fileConfigMap, "checkCRL", targetSslConfig::setCheckCRL);
    }

    /** Helper functional interface for applying string settings. */
    @FunctionalInterface
    private interface StringSetter { void set(String value); }
    /** Helper functional interface for applying integer settings. */
    @FunctionalInterface
    private interface IntSetter { void set(int value); }
    /** Helper functional interface for applying boolean settings. */
    @FunctionalInterface
    private interface BooleanSetter { void set(boolean value); }
    /** Helper functional interface for applying File settings. */
    @FunctionalInterface
    private interface FileSetter { void set(File value); }
    /** Helper functional interface for applying Enum settings. */
    @FunctionalInterface
    private interface EnumSetter<E extends Enum<E>> { void set(E value); }

    private static void applyString(Map<String, Object> config, String key, StringSetter setter) {
        if (config.containsKey(key)) {
            try {
                setter.set(config.get(key).toString());
                logger.debug("Applied config: {} = {}", key, config.get(key).toString());
            } catch (Exception e) {
                logger.warn("Error applying string config for key '{}': {}", key, e.getMessage());
            }
        }
    }

    private static void applyInt(Map<String, Object> config, String key, IntSetter setter) {
        if (config.containsKey(key)) {
            try {
                setter.set(Integer.parseInt(config.get(key).toString()));
                logger.debug("Applied config: {} = {}", key, config.get(key).toString());
            } catch (NumberFormatException e) {
                logger.warn("Error parsing integer for config key '{}' (value: '{}'): {}", key, config.get(key), e.getMessage());
            } catch (Exception e) {
                logger.warn("Error applying integer config for key '{}': {}", key, e.getMessage());
            }
        }
    }

    private static void applyBoolean(Map<String, Object> config, String key, BooleanSetter setter) {
        if (config.containsKey(key)) {
            try {
                setter.set(Boolean.parseBoolean(config.get(key).toString()));
                logger.debug("Applied config: {} = {}", key, config.get(key).toString());
            } catch (Exception e) {
                logger.warn("Error applying boolean config for key '{}': {}", key, e.getMessage());
            }
        }
    }

    private static void applyFile(Map<String, Object> config, String key, FileSetter setter) {
        if (config.containsKey(key)) {
            try {
                setter.set(new File(config.get(key).toString()));
                logger.debug("Applied config: {} = {}", key, config.get(key).toString());
            } catch (Exception e) {
                logger.warn("Error applying file config for key '{}': {}", key, e.getMessage());
            }
        }
    }

    private static <E extends Enum<E>> void applyEnum(Map<String, Object> config, String key, Class<E> enumClass, EnumSetter<E> setter) {
        if (config.containsKey(key)) {
            try {
                setter.set(Enum.valueOf(enumClass, config.get(key).toString().toUpperCase()));
                logger.debug("Applied config: {} = {}", key, config.get(key).toString().toUpperCase());
            } catch (IllegalArgumentException e) {
                logger.warn("Error parsing enum for config key '{}' (value: '{}'): {}", key, config.get(key), e.getMessage());
            } catch (Exception e) {
                logger.warn("Error applying enum config for key '{}': {}", key, e.getMessage());
            }
        }
    }
}