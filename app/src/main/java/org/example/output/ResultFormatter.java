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

public class ResultFormatter {
    private static final Logger logger = LoggerFactory.getLogger(ResultFormatter.class);
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final SSLTestConfig config;

    public ResultFormatter(SSLTestConfig config) {
        this.config = config;
    }

    public void formatAndOutput(Map<String, Object> result) {
        try {
            String output;
            switch (config.getFormat()) {
                case JSON:
                    output = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
                    break;
                case YAML:
                    output = yamlMapper.writeValueAsString(result);
                    break;
                case TEXT:
                    if (result instanceof SSLConnectionResult) {
                        // 如果是SSLConnectionResult，将其转换为Map以使用统一的格式化方法
                        Map<String, Object> resultMap = new HashMap<>();
                        resultMap.put("httpStatus", ((SSLConnectionResult) result).getHttpStatus());
                        resultMap.put("cipherSuite", ((SSLConnectionResult) result).getCipherSuite());
                        resultMap.put("hostnameVerified", ((SSLConnectionResult) result).isHostnameVerified());
                        resultMap.put("certificateChain", ((SSLConnectionResult) result).getCertificateChain());
                        output = formatTextOutput(resultMap);
                    } else if (result.containsKey("certificateChain") && !((List<?>) result.get("certificateChain")).isEmpty()) {
                        output = formatTextOutput(result);
                    } else {
                        output = formatSimpleText(result);
                    }
                    break;
                default:
                    return;
            }

            if (config.getOutputFile() != null) {
                try (FileWriter writer = new FileWriter(config.getOutputFile())) {
                    writer.write(output);
                    writer.flush();
                } catch (IOException e) {
                    logger.error("Error writing to output file", e);
                }
            } else {
                System.out.println(output);
            }
        } catch (Exception e) {
            logger.error("输出结果时发生错误: {}", e.getMessage());
        }
    }

    private String formatTextOutput(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();

        // General connection info
        if (result.containsKey("httpStatus")) {
            sb.append("→ HTTP Status         : ").append(result.get("httpStatus")).append("\n");
        }
        if (result.containsKey("cipherSuite")) {
            sb.append("→ Cipher Suite        : ").append(result.get("cipherSuite")).append("\n");
        }
        if (result.containsKey("hostnameVerified")) {
            sb.append("→ Hostname Verification: ").append(Boolean.TRUE.equals(result.get("hostnameVerified")) ? "Passed" : "Failed").append("\n");
        }
        if (result.containsKey("status") && "success".equals(result.get("status"))) {
             sb.append("→ Overall Status      : Success\n");
        } else if (result.containsKey("error")) {
             sb.append("→ Overall Status      : FAILED\n");
        }


        // Certificate chain details
        Object certChainObj = result.get("certificateChain");
        if (certChainObj instanceof List<?> certs && !certs.isEmpty()) {
            sb.append("→ Server Certificate Chain (").append(certs.size()).append(" certificate(s)):\n");
            for (int i = 0; i < certs.size(); i++) {
                Object certObj = certs.get(i);
                if (certObj instanceof Map<?, ?> certMap) { // Use a more specific variable name
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
                    if (certMap.containsKey("ocspResponderUrl") && certMap.get("ocspResponderUrl") != null && !((String)certMap.get("ocspResponderUrl")).isEmpty()) {
                        sb.append("    OCSP Responder URL: ").append(certMap.get("ocspResponderUrl")).append("\n");
                    }
                    if (certMap.containsKey("crlDistributionPoints") && certMap.get("crlDistributionPoints") != null && !((List<?>)certMap.get("crlDistributionPoints")).isEmpty()) {
                        sb.append("    CRL Distrib. Points: ").append(certMap.get("crlDistributionPoints").toString()).append("\n");
                    }
                    
                    // Failure Reason (conditionally displayed based on status)
                    Object trustStatus = certMap.get("trustStatus");
                    Object revocationStatus = certMap.get("revocationStatus");
                    if (certMap.containsKey("failureReason") && certMap.get("failureReason") != null && !((String)certMap.get("failureReason")).isEmpty()) {
                        boolean trustNotOk = "NOT_TRUSTED".equals(trustStatus) || "UNKNOWN".equals(trustStatus);
                        boolean revokeNotOk = "REVOKED".equals(revocationStatus) || "UNKNOWN".equals(revocationStatus);
                        if (trustNotOk || revokeNotOk) {
                             sb.append("    Failure Reason    : ").append(certMap.get("failureReason")).append("\n");
                        } else {
                             // Optionally log if there's a failure reason but statuses are good (might indicate logic error)
                             logger.debug("Certificate has failureReason but status is OK: Subject {}, Trust: {}, Revoke: {}", certMap.get("subjectDN"), trustStatus, revocationStatus);
                        }
                    }

                    // Subject Alternative Names
                    Object sansObj = cert.get("subjectAlternativeNames");
                    if (sansObj instanceof Map<?, ?> sansMap) { // Check if it's a Map
                        if (!sansMap.isEmpty()) {
                            sb.append("    Subject Alternative Names:\n");
                            for (Map.Entry<?, ?> sanEntry : sansMap.entrySet()) {
                                sb.append("        Type ").append(sanEntry.getKey()).append(": ").append(sanEntry.getValue()).append("\n");
                            }
                        }
                    } else if (sansObj instanceof List<?> sanList) { // Check if it's a list (for CRL points, etc.)
                        if (!sanList.isEmpty()) {
                            // This part might need specific formatting depending on what sanList contains
                            // For now, just printing it as a list.
                            sb.append("    SAN (List)    : ").append(sansObj.toString()).append("\n");
                        }
                    } else if (sansObj != null) {
                        // Handle other types or log a warning
                        sb.append("    SAN (Unknown) : ").append(sansObj.toString()).append("\n");
                    }
                }
            }
        }

        // 处理错误信息
        if (result.containsKey("error")) {
            sb.append("\n错误信息:\n");
            sb.append(result.get("error")).append("\n");
            if (result.containsKey("errorCause")) {
                sb.append("原因: ").append(result.get("errorCause")).append("\n");
            }
        }

        return sb.toString();
    }

    private String formatSimpleText(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();
        
        // 添加基本连接信息
        if (result.containsKey("status")) {
            sb.append("连接状态: ").append(result.get("status")).append("\n");
        }
        if (result.containsKey("httpStatus")) {
            sb.append("HTTP状态码: ").append(result.get("httpStatus")).append("\n");
        }
        if (result.containsKey("cipherSuite")) {
            sb.append("协商的密码套件: ").append(result.get("cipherSuite")).append("\n");
        }
        if (result.containsKey("hostnameVerified")) {
            sb.append("主机名验证: ").append(Boolean.TRUE.equals(result.get("hostnameVerified")) ? "通过" : "失败").append("\n");
        }

        // 处理错误信息
        if (result.containsKey("error")) {
            sb.append("\n错误信息:\n");
            sb.append(result.get("error")).append("\n");
            if (result.containsKey("errorCause")) {
                sb.append("原因: ").append(result.get("errorCause")).append("\n");
            }
        }

        return sb.toString();
    }

    public void logError(String message, Throwable cause, int exitCode) {
        logger.error("❌ {}", message);
        if (cause != null && config.isVerbose()) {
            logger.error("详细错误信息:", cause);
        }
    }
}

