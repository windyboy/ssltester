package org.example.output

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import org.example.config.SSLTestConfig
import org.example.ssl.SSLConnectionResult
import org.slf4j.LoggerFactory
import java.io.FileWriter
import java.io.IOException

/**
 * Handles the formatting of SSL/TLS test results into various output formats
 * (TEXT, JSON, YAML) and directs the output to the configured destination,
 * which can be a file or the standard console.
 */
class ResultFormatter(private val config: SSLTestConfig) {
    private val logger = LoggerFactory.getLogger(ResultFormatter::class.java)
    private val jsonMapper = ObjectMapper()
    private val yamlMapper = ObjectMapper(YAMLFactory())

    /**
     * Formats the provided result map into the configured output format (TEXT, JSON, or YAML)
     * and writes it to the specified output file or to the console if no file is set.
     */
    fun formatAndOutput(result: Any) {
        try {
            val output = when (config.format) {
                SSLTestConfig.OutputFormat.JSON -> when (result) {
                    is SSLConnectionResult -> jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result)
                    is Map<*, *> -> jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result)
                    else -> throw IllegalArgumentException("Unsupported result type for JSON output")
                }
                SSLTestConfig.OutputFormat.YAML -> when (result) {
                    is SSLConnectionResult -> yamlMapper.writeValueAsString(result)
                    is Map<*, *> -> yamlMapper.writeValueAsString(result)
                    else -> throw IllegalArgumentException("Unsupported result type for YAML output")
                }
                SSLTestConfig.OutputFormat.TEXT -> when (result) {
                    is SSLConnectionResult -> {
                        val resultMap = mapOf(
                            "httpStatus" to result.httpStatus,
                            "cipherSuite" to result.cipherSuite,
                            "hostnameVerified" to result.hostnameVerified,
                            "certificateChain" to result.certificateChain
                        )
                        formatCertificateOutput(resultMap)
                    }
                    is Map<*, *> -> {
                        @Suppress("UNCHECKED_CAST")
                        val typedMap = result as Map<String, Any>
                        if (typedMap.containsKey("certificateChain") && (typedMap["certificateChain"] as? List<*>)?.isNotEmpty() == true) {
                            formatCertificateOutput(typedMap)
                        } else {
                            formatSimpleText(typedMap)
                        }
                    }
                    else -> throw IllegalArgumentException("Unsupported result type for TEXT output")
                }
            }

            config.outputFile?.let { file ->
                try {
                    FileWriter(file).use { writer ->
                        writer.write(output)
                        writer.flush()
                    }
                    logger.info("Results written to: {}", file.absolutePath)
                } catch (e: IOException) {
                    logger.error("Error writing to output file", e)
                }
            } ?: run {
                print(output) // Use print for consistency
            }
        } catch (e: Exception) {
            logger.error("Error writing results: {}", e.message, e)
        }
    }

    private fun formatCertificateOutput(result: Map<String, Any>): String {
        val sb = StringBuilder()
        
        // Add basic connection information
        result["httpStatus"]?.let { sb.append("→ HTTP Status  : $it\n") }
        result["cipherSuite"]?.let { sb.append("→ Cipher Suite : $it\n") }
        result["hostnameVerified"]?.let { 
            sb.append("→ Hostname verification ${if (it == true) "passed" else "failed"}\n") 
        }

        // Add certificate information
        (result["certificateChain"] as? List<*>)?.let { certs ->
            if (certs.isNotEmpty()) {
                sb.append("→ Server sent ${certs.size} certificate(s):\n")
                certs.forEachIndexed { index, certObj ->
                    (certObj as? Map<*, *>)?.let { cert ->
                        sb.append("\nCertificate [${index + 1}]\n")
                        
                        // Basic information
                        cert["subjectDN"]?.let { sb.append("    Subject DN    : $it\n") }
                        cert["issuerDN"]?.let { sb.append("    Issuer DN     : $it\n") }
                        cert["version"]?.let { sb.append("    Version       : $it\n") }
                        cert["serialNumber"]?.let { sb.append("    Serial Number : $it\n") }
                        cert["validFrom"]?.let { sb.append("    Valid From    : $it\n") }
                        cert["validUntil"]?.let { sb.append("    Valid Until   : $it\n") }
                        cert["signatureAlgorithm"]?.let { sb.append("    Sig. Algorithm: $it\n") }
                        cert["publicKeyAlgorithm"]?.let { sb.append("    PubKey Alg    : $it\n") }
                        
                        // Certificate status information
                        cert["status"]?.let { sb.append("    Status        : $it\n") }
                        cert["trusted"]?.let { sb.append("    Trusted       : $it\n") }
                        cert["expired"]?.let { sb.append("    Expired       : $it\n") }
                        cert["notYetValid"]?.let { sb.append("    Not Yet Valid : $it\n") }
                        cert["revoked"]?.let { sb.append("    Revoked       : $it\n") }
                        cert["selfSigned"]?.let { sb.append("    Self Signed   : $it\n") }
                        
                        // Subject Alternative Names
                        (cert["subjectAlternativeNames"] as? Map<*, *>)?.let { sans ->
                            if (sans.isNotEmpty()) {
                                sb.append("    Subject Alternative Names:\n")
                                sans.forEach { (type, value) ->
                                    sb.append("        Type $type: $value\n")
                                }
                            }
                        }
                    }
                }
            }
        }

        // Handle error information
        result["error"]?.let {
            sb.append("\nError:\n$it\n")
            result["errorCause"]?.let { cause ->
                sb.append("Cause: $cause\n")
            }
        }

        return sb.toString()
    }

    private fun formatSimpleText(result: Map<String, Any>): String {
        val sb = StringBuilder()
        
        // Add basic connection information
        result["status"]?.let { sb.append("Connection Status: $it\n") }
        result["httpStatus"]?.let { sb.append("HTTP Status: $it\n") }
        result["cipherSuite"]?.let { sb.append("Cipher Suite: $it\n") }
        result["hostnameVerified"]?.let { 
            sb.append("Hostname Verification: ${if (it == true) "Passed" else "Failed"}\n") 
        }

        // Handle error information
        result["error"]?.let {
            sb.append("\nError:\n$it\n")
            result["errorCause"]?.let { cause ->
                sb.append("Cause: $cause\n")
            }
        }

        return sb.toString()
    }

    /**
     * Logs an error message and its cause.
     * @param message The error message
     * @param cause The cause of the error
     * @param exitCode The exit code associated with the error
     */
    fun logError(message: String, cause: Throwable?, exitCode: Int) {
        logger.error("Error: {}", message)
        cause?.let {
            logger.error("Cause: {}", it.message)
            if (config.verbose) {
                logger.error("Stack trace:", it)
            }
        }
        logger.error("Exit code: {}", exitCode)
    }
} 