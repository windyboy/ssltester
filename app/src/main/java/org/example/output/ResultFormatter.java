package org.example.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.example.config.SSLTestConfig;
import org.example.ssl.SSLConnectionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Formats the results of the SSL test into various output formats (TEXT, JSON, YAML).
 * It takes a map of results and outputs it to either standard output or a specified file.
 */
public class ResultFormatter {
    private static final Logger logger = LoggerFactory.getLogger(ResultFormatter.class);
    /** Jackson ObjectMapper for JSON serialization. Configured for pretty printing. */
    private final ObjectMapper jsonMapper = new ObjectMapper();
    /** Jackson ObjectMapper for YAML serialization. */
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    /** Configuration for the SSL test, used to determine output format and file. */
    private final SSLTestConfig config;

    /**
     * Constructs a ResultFormatter with the given SSL test configuration.
     *
     * @param config The {@link SSLTestConfig} which specifies output preferences like format and file.
     *               Must not be null.
     */
    public ResultFormatter(SSLTestConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("SSLTestConfig cannot be null for ResultFormatter.");
        }
        this.config = config;
        // Ensure pretty printing for JSON by default
        this.jsonMapper.writerWithDefaultPrettyPrinter(); 
    }

    /**
     * Formats the provided result map according to the configured output format (JSON, YAML, or TEXT)
     * and writes it to the configured output file or standard output.
     *
     * @param result A map containing the key-value pairs of the test results.
     *               This map is expected to be populated by {@link SSLTest}.
     */
    public void formatAndOutput(Map<String, Object> result) {
        try {
            String outputString;
            SSLTestConfig.OutputFormat format = config.getFormat();
            logger.debug("Formatting results for output as {}.", format);

            switch (format) {
                case JSON:
                    outputString = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
                    break;
                case YAML:
                    outputString = yamlMapper.writeValueAsString(result);
                    break;
                case TEXT:
                    // The SSLConnectionResult type is not used; results are always passed as Map.
                    // Check if the result map contains certificate chain details for detailed text formatting.
                    if (result.containsKey("certificateChain") && 
                        result.get("certificateChain") instanceof List && 
                        !((List<?>) result.get("certificateChain")).isEmpty()) {
                        outputString = formatTextOutput(result);
                    } else {
                        // Fallback for simpler results or error outputs that might not have a certificate chain.
                        outputString = formatSimpleText(result);
                    }
                    break;
                default:
                    logger.warn("Unsupported output format configured: {}. No output will be generated.", format);
                    return;
            }

            if (config.getOutputFile() != null) {
                File outputFile = config.getOutputFile();
                logger.info("Writing output to file: {}", outputFile.getAbsolutePath());
                try (FileWriter writer = new FileWriter(outputFile)) {
                    writer.write(outputString);
                    writer.flush();
                    logger.debug("Successfully wrote output to {}.", outputFile.getAbsolutePath());
                } catch (IOException e) {
                    logger.error("Error writing output to file {}: {}", outputFile.getAbsolutePath(), e.getMessage(), e);
                    // Also print to console as a fallback if file writing fails
                    System.err.println("Failed to write to output file. Displaying to console instead:\n" + outputString);
                }
            } else {
                logger.debug("Writing output to standard console.");
                System.out.println(outputString);
            }
        } catch (Exception e) {
            logger.error("Error formatting or outputting results: {}", e.getMessage(), e);
            // Fallback: print raw result map to error stream if formatting fails.
            System.err.println("Critical error during output formatting. Raw result: " + result.toString());
        }
    }

    /**
     * Formats the detailed test results, including certificate chain information, as plain text.
     *
     * @param result The result map, expected to contain keys like "httpStatus", "cipherSuite",
     *               "hostnameVerified", "certificateChain", and potentially "error".
     * @return A string representation of the formatted results for text output.
     */
    private String formatTextOutput(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();
        logger.debug("Formatting detailed text output.");

        // General connection info
        sb.append("SSL Test Results:\n");
        sb.append("--------------------------------------------------\n");
        if (result.containsKey("status") && "success".equals(result.get("status"))) {
             sb.append("→ Overall Status      : Success\n");
        } else if (result.containsKey("error")) { // If there's an error, overall status is FAILED
             sb.append("→ Overall Status      : FAILED\n");
        }
        if (result.containsKey("httpStatus")) {
            sb.append("→ HTTP Status         : ").append(result.get("httpStatus")).append("\n");
        }
        if (result.containsKey("cipherSuite")) {
            sb.append("→ Cipher Suite        : ").append(result.get("cipherSuite")).append("\n");
        }
        if (result.containsKey("hostnameVerified")) {
            sb.append("→ Hostname Verification: ").append(Boolean.TRUE.equals(result.get("hostnameVerified")) ? "Passed" : "Failed").append("\n");
        }
        sb.append("--------------------------------------------------\n");


        // Certificate chain details
        Object certChainObj = result.get("certificateChain");
        if (certChainObj instanceof List<?> certsList && !certsList.isEmpty()) {
            sb.append("Server Certificate Chain (").append(certsList.size()).append(" certificate(s)):\n");
            for (int i = 0; i < certsList.size(); i++) {
                if (!(certsList.get(i) instanceof Map<?, ?> certMap)) {
                    sb.append("\n  Certificate [").append(i + 1).append("]: Invalid data format in results.\n");
                    continue;
                }
                sb.append("\n  Certificate [").append(i + 1).append("]:\n");
                
                // Basic Info
                sb.append("    Subject DN        : ").append(certMap.getOrDefault("subjectDN", "N/A")).append("\n");
                sb.append("    Issuer DN         : ").append(certMap.getOrDefault("issuerDN", "N/A")).append("\n");
                sb.append("    Serial Number     : ").append(certMap.getOrDefault("serialNumber", "N/A")).append("\n");
                sb.append("    Version           : ").append(certMap.getOrDefault("version", "N/A")).append("\n");
                sb.append("    Valid From        : ").append(certMap.getOrDefault("validFrom", "N/A")).append("\n");
                sb.append("    Valid Until       : ").append(certMap.getOrDefault("validUntil", "N/A")).append("\n");
                sb.append("    Signature Algorithm: ").append(certMap.getOrDefault("signatureAlgorithm", "N/A")).append("\n");
                sb.append("    Public Key Alg.   : ").append(certMap.getOrDefault("publicKeyAlgorithm", "N/A")).append("\n");

                // Status Flags
                sb.append("    Is Self-Signed    : ").append(certMap.getOrDefault("selfSigned", "false")).append("\n");
                sb.append("    Is Expired        : ").append(certMap.getOrDefault("expired", "false")).append("\n");
                sb.append("    Is Not Yet Valid  : ").append(certMap.getOrDefault("notYetValid", "false")).append("\n");

                // Trust and Revocation
                sb.append("    Trust Status      : ").append(certMap.getOrDefault("trustStatus", "UNKNOWN")).append("\n");
                sb.append("    Revocation Status : ").append(certMap.getOrDefault("revocationStatus", "NOT_CHECKED")).append("\n");

                // OCSP/CRL Info
                Object ocspUrl = certMap.get("ocspResponderUrl");
                if (ocspUrl instanceof String && !((String)ocspUrl).isEmpty()) {
                    sb.append("    OCSP Responder URL: ").append(ocspUrl).append("\n");
                }
                Object crlPoints = certMap.get("crlDistributionPoints");
                if (crlPoints instanceof List && !((List<?>)crlPoints).isEmpty()) {
                    sb.append("    CRL Distrib. Points: ").append(crlPoints.toString()).append("\n");
                }
                
                // Failure Reason (conditionally displayed based on status for clarity)
                Object failureReasonObj = certMap.get("failureReason");
                if (failureReasonObj instanceof String failureReasonStr && !failureReasonStr.isEmpty()) {
                    Object trustStatus = certMap.get("trustStatus");
                    Object revocationStatus = certMap.get("revocationStatus");
                    boolean trustNotOk = "NOT_TRUSTED".equals(trustStatus) || "UNKNOWN".equals(trustStatus);
                    // For revocation, UNKNOWN might have a failure reason (e.g. responder unavailable)
                    boolean revokeNotOkOrUnknown = "REVOKED".equals(revocationStatus) || "UNKNOWN".equals(revocationStatus);
                    
                    if (trustNotOk || revokeNotOkOrUnknown) {
                         sb.append("    Failure Reason    : ").append(failureReasonStr).append("\n");
                    } else {
                         // Log if there's a failure reason but primary statuses seem okay (could indicate an issue or minor note)
                         logger.debug("Certificate has failureReason '{}' but status is OK: Subject {}, Trust: {}, Revoke: {}", 
                                      failureReasonStr, certMap.get("subjectDN"), trustStatus, revocationStatus);
                         // Optionally, display it anyway if it's considered important regardless of primary status.
                         // sb.append("    Note              : ").append(failureReasonStr).append("\n");
                    }
                }

                // Subject Alternative Names (SANs)
                Object sansObj = certMap.get("subjectAlternativeNames");
                if (sansObj instanceof Map<?, ?> rawSansMap) {
                    @SuppressWarnings("unchecked") // Ensure this cast is safe or handle appropriately
                    Map<String, List<String>> sansMap = (Map<String, List<String>>) rawSansMap;
                    if (!sansMap.isEmpty()) {
                        sb.append("    Subject Alternative Names:\n");
                        for (Map.Entry<String, List<String>> sanTypeEntry : sansMap.entrySet()) {
                            String typeKey = sanTypeEntry.getKey(); // This is the SAN type number as a String
                            List<String> sanValues = sanTypeEntry.getValue();
                            for (String sanValue : sanValues) {
                                sb.append("        Type ").append(typeKey).append(": ").append(sanValue).append("\n");
                            }
                        }
                    }
                }
            }
        } else {
            sb.append("  No certificate chain information available.\n");
        }
        sb.append("--------------------------------------------------\n");

        // Error information (if any)
        if (result.containsKey("error")) {
            sb.append("\nError Information:\n");
            sb.append("  Message: ").append(result.get("error")).append("\n");
            if (result.containsKey("errorCause")) {
                sb.append("  Cause  : ").append(result.get("errorCause")).append("\n");
            }
             if (result.containsKey("exitCode")) {
                sb.append("  Exit Code: ").append(result.get("exitCode")).append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Formats a simple text output, typically used for errors or results without detailed certificate chains.
     *
     * @param result The result map, usually containing an "error" or basic "status" information.
     * @return A string representation for simple text output.
     */
    private String formatSimpleText(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();
        logger.debug("Formatting simple text output.");
        
        if (result.containsKey("status")) {
            sb.append("Status: ").append(result.get("status")).append("\n");
        }
        if (result.containsKey("httpStatus")) {
            sb.append("HTTP Status Code: ").append(result.get("httpStatus")).append("\n");
        }
        if (result.containsKey("cipherSuite")) {
            sb.append("Cipher Suite: ").append(result.get("cipherSuite")).append("\n");
        }
        if (result.containsKey("hostnameVerified")) {
            sb.append("Hostname Verification: ").append(Boolean.TRUE.equals(result.get("hostnameVerified")) ? "Passed" : "Failed").append("\n");
        }

        if (result.containsKey("error")) {
            sb.append("\nError Information:\n");
            sb.append("  Message: ").append(result.get("error")).append("\n");
            if (result.containsKey("errorCause")) {
                sb.append("  Cause  : ").append(result.get("errorCause")).append("\n");
            }
            if (result.containsKey("exitCode")) {
                sb.append("  Exit Code: ").append(result.get("exitCode")).append("\n");
            }
        } else if (sb.length() == 0) { // If no other info, just print the map
            sb.append("Result:\n");
            result.forEach((key, value) -> sb.append("  ").append(key).append(": ").append(value).append("\n"));
        }

        return sb.toString();
    }

    /**
     * Logs an error message. If verbose logging is enabled in the configuration,
     * it also logs the full stack trace of the cause.
     *
     * @param message   The error message to log.
     * @param cause     The throwable that caused the error (can be null).
     * @param exitCode  The exit code associated with this error.
     */
    public void logError(String message, Throwable cause, int exitCode) {
        logger.error("❌ Error (Exit Code {}): {}", exitCode, message);
        if (cause != null && config.isVerbose()) {
            logger.error("Detailed error information:", cause);
        } else if (cause != null) {
            logger.debug("Error cause (enable verbose for full trace): {}", cause.getMessage());
        }
    }
}

