package org.example.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.example.exception.SSLTestException
import java.io.File

/**
 * Utility class for loading SSL test configuration from files.
 */
object SSLTestConfigFile {
    private val jsonMapper = ObjectMapper().registerKotlinModule()
    private val yamlMapper = ObjectMapper(YAMLFactory()).registerKotlinModule()

    /**
     * Loads configuration from a file.
     * @param file The configuration file
     * @return The loaded configuration
     * @throws SSLTestException if loading fails
     */
    fun load(file: File): SSLTestConfig {
        try {
            return when {
                file.name.endsWith(".json") -> jsonMapper.readValue(file)
                file.name.endsWith(".yaml", ignoreCase = true) || file.name.endsWith(".yml", ignoreCase = true) -> yamlMapper.readValue(file)
                else -> throw SSLTestException("Unsupported configuration file format: ${file.name}")
            }
        } catch (e: Exception) {
            throw SSLTestException("Failed to load configuration file: ${e.message}", cause = e)
        }
    }
} 