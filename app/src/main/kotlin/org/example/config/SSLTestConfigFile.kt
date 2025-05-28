package org.example.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException

class SSLTestConfigFile {
    companion object {
        private val logger = LoggerFactory.getLogger(SSLTestConfigFile::class.java)
        private val YAML_MAPPER = ObjectMapper(YAMLFactory())
        private val JSON_MAPPER = ObjectMapper()

        @Suppress("UNCHECKED_CAST")
        fun loadConfig(configFile: File): Map<String, Any> {
            if (!configFile.exists()) {
                throw IOException("Configuration file does not exist: $configFile")
            }

            return when {
                configFile.name.lowercase().endsWith(".yaml") || configFile.name.lowercase().endsWith(".yml") -> {
                    YAML_MAPPER.readValue(configFile, HashMap::class.java) as Map<String, Any>
                }
                configFile.name.lowercase().endsWith(".json") -> {
                    JSON_MAPPER.readValue(configFile, HashMap::class.java) as Map<String, Any>
                }
                else -> throw IOException("Unsupported configuration file format. Use .yaml, .yml, or .json")
            }
        }

        fun applyConfig(config: Map<String, Any>?, sslConfig: SSLTestConfig) {
            if (config == null) return

            try {
                config.forEach { (key, value) ->
                    when (key) {
                        "connectionTimeout" -> sslConfig.connectionTimeout = value.toString().toInt()
                        "readTimeout" -> sslConfig.readTimeout = value.toString().toInt()
                        "followRedirects" -> sslConfig.followRedirects = value.toString().toBoolean()
                        "keystoreFile" -> sslConfig.keystoreFile = File(value.toString())
                        "keystorePassword" -> sslConfig.keystorePassword = value.toString()
                        "outputFile" -> sslConfig.outputFile = File(value.toString())
                        "format" -> sslConfig.format = SSLTestConfig.OutputFormat.valueOf(value.toString().uppercase())
                        "verbose" -> sslConfig.verbose = value.toString().toBoolean()
                    }
                }
            } catch (e: Exception) {
                logger.warn("Error applying configuration: {}", e.message)
            }
        }
    }
} 