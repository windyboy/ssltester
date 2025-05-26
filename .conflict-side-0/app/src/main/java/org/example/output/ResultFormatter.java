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
 * Handles the formatting of SSL/TLS test results into various output formats
 * (TEXT, JSON, YAML) and directs the output to the configured destination,
 * which can be a file or the standard console.
 */
public class ResultFormatter {
    private static final Logger logger = LoggerFactory.getLogger(ResultFormatter.class);
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final SSLTestConfig config;

    /**
     * Constructs a ResultFormatter with the given SSLTestConfig.
     * The configuration is used to determine output format, destination, and verbosity.
     *
     * @param config The SSLTestConfig containing output settings.
     */
    public ResultFormatter(SSLTestConfig config) {
        this.config = config;
    }

    /**
     * Formats the provided result map into the configured output format (TEXT, JSON, or YAML)
     * and writes it to the specified output file or to the console if no file is set.
     *
     * For TEXT format, it generates a human-readable string representation of the map.
     * For JSON and YAML, it uses Jackson library for pretty-printed output.
     *
     * @param result The map containing the test results to be formatted and output.
     */
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
                        output = formatCertificateOutput(resultMap);
                    } else if (result.containsKey("certificateChain") && !((List<?>) result.get("certificateChain")).isEmpty()) {
                        output = formatCertificateOutput(result);
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
                logger.info("Results written to: {}", config.getOutputFile().getAbsolutePath());
            } else {
                System.out.print(output); // Use print for consistency
            }
        } catch (Exception e) {
            logger.error("Error writing results: {}", e.getMessage(), e); // English error message
        }
    }

    private String formatCertificateOutput(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();
        
        // 添加基本连接信息
        if (result.containsKey("httpStatus")) {
            sb.append("→ HTTP Status  : ").append(result.get("httpStatus")).append("\n");
        }
        if (result.containsKey("cipherSuite")) {
            sb.append("→ Cipher Suite : ").append(result.get("cipherSuite")).append("\n");
        }
        if (result.containsKey("hostnameVerified")) {
            sb.append("→ Hostname verification ").append(Boolean.TRUE.equals(result.get("hostnameVerified")) ? "passed" : "failed").append("\n");
        }

        // 添加证书信息
        Object certChainObj = result.get("certificateChain");
        if (certChainObj instanceof List<?> certs && !certs.isEmpty()) {
            sb.append("→ Server sent ").append(certs.size()).append(" certificate(s):\n");
            for (int i = 0; i < certs.size(); i++) {
                Object certObj = certs.get(i);
                if (certObj instanceof Map<?, ?> cert) {
                    sb.append("\nCertificate [").append(i + 1).append("]\n");
                    
                    // 基本信息
                    if (cert.containsKey("subjectDN")) {
                        sb.append("    Subject DN    : ").append(cert.get("subjectDN")).append("\n");
                    }
                    if (cert.containsKey("issuerDN")) {
                        sb.append("    Issuer DN     : ").append(cert.get("issuerDN")).append("\n");
                    }
                    if (cert.containsKey("version")) {
                        sb.append("    Version       : ").append(cert.get("version")).append("\n");
                    }
                    if (cert.containsKey("serialNumber")) {
                        sb.append("    Serial Number : ").append(cert.get("serialNumber")).append("\n");
                    }
                    if (cert.containsKey("validFrom")) {
                        sb.append("    Valid From    : ").append(cert.get("validFrom")).append("\n");
                    }
                    if (cert.containsKey("validUntil")) {
                        sb.append("    Valid Until   : ").append(cert.get("validUntil")).append("\n");
                    }
                    if (cert.containsKey("signatureAlgorithm")) {
                        sb.append("    Sig. Algorithm: ").append(cert.get("signatureAlgorithm")).append("\n");
                    }
                    if (cert.containsKey("publicKeyAlgorithm")) {
                        sb.append("    PubKey Alg    : ").append(cert.get("publicKeyAlgorithm")).append("\n");
                    }
                    
                    // 证书状态信息
                    if (cert.containsKey("status")) {
                        sb.append("    Status        : ").append(cert.get("status")).append("\n");
                    }
                    if (cert.containsKey("trusted")) {
                        sb.append("    Trusted       : ").append(cert.get("trusted")).append("\n");
                    }
                    if (cert.containsKey("expired")) {
                        sb.append("    Expired       : ").append(cert.get("expired")).append("\n");
                    }
                    if (cert.containsKey("notYetValid")) {
                        sb.append("    Not Yet Valid : ").append(cert.get("notYetValid")).append("\n");
                    }
                    if (cert.containsKey("revoked")) {
                        sb.append("    Revoked       : ").append(cert.get("revoked")).append("\n");
                    }
                    if (cert.containsKey("selfSigned")) {
                        sb.append("    Self Signed   : ").append(cert.get("selfSigned")).append("\n");
                    }
                    
                    // Subject Alternative Names
                    if (cert.containsKey("subjectAlternativeNames")) {
                        Object sansObj = cert.get("subjectAlternativeNames");
                        if (sansObj instanceof Map<?, ?> sans) {
                            if (!sans.isEmpty()) {
                                sb.append("    Subject Alternative Names:\n");
                                for (Map.Entry<?, ?> san : sans.entrySet()) {
                                    sb.append("        Type ").append(san.getKey()).append(": ").append(san.getValue()).append("\n");
                                }
                            }
                        }
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
            logger.error("Detailed error information:", cause);
        }
    }
}

