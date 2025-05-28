package org.example.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException

/**
 * Handles loading and parsing of configuration files in YAML format.
 */
object SSLTestConfigFile {
    private val logger = LoggerFactory.getLogger(SSLTestConfigFile::class.java)
    private val yamlMapper = ObjectMapper(YAMLFactory()).registerKotlinModule()

    /**
     * Loads configuration from a YAML file.
     *
     * @param configFile The path to the configuration file
     * @return A map containing the configuration values
     * @throws IOException if the file cannot be read or parsed
     */
    fun loadConfig(configFile: String): Map<String, Any> {
        return try {
            yamlMapper.readValue(File(configFile))
        } catch (e: IOException) {
            throw IOException("Failed to load configuration file: ${e.message}", e)
        }
    }

    /**
     * Applies configuration values from a map to an SSLTestConfig object.
     *
     * @param configMap The map containing configuration values
     * @param config The SSLTestConfig object to update
     */
    fun applyConfig(configMap: Map<String, Any>, config: SSLTestConfig) {
        configMap.forEach { (key, value) ->
            when (key) {
                "connectionTimeout" -> config.connectionTimeout = (value as Number).toInt()
                "readTimeout" -> config.readTimeout = (value as Number).toInt()
                "followRedirects" -> config.followRedirects = value as Boolean
                "keystoreFile" -> config.keystoreFile = File(value as String)
                "keystorePassword" -> config.keystorePassword = value as String
                "clientCertFile" -> config.clientCertFile = File(value as String)
                "clientKeyFile" -> config.clientKeyFile = File(value as String)
                "clientKeyPassword" -> config.clientKeyPassword = value as String
                "outputFile" -> config.outputFile = File(value as String)
                "format" -> config.format = SSLTestConfig.OutputFormat.valueOf((value as String).uppercase())
                "trustAllHosts" -> config.trustAllHosts = value as Boolean
                "failOnError" -> config.failOnError = value as Boolean
                "verbose" -> config.verbose = value as Boolean
            }
        }
    }
} 