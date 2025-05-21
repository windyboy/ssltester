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
            } else {
                System.out.println(output);
            }
        } catch (Exception e) {
            logger.error("输出结果时发生错误: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getCertificates(Map<String, Object> result) {
        Object certs = result.get("certificates");
        if (certs instanceof List) {
            return (List<Map<String, Object>>) certs;
        }
        return List.of();
    }

    private String formatTextOutput(Map<String, Object> result) {
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
        sb.append("\n");

        // 处理证书信息
        List<Map<String, Object>> certs = getCertificates(result);
        if (!certs.isEmpty()) {
            sb.append("证书链:\n");
            for (Map<String, Object> cert : certs) {
                sb.append("\n[").append(cert.get("position")).append("] ").append(cert.get("level")).append("\n");
                sb.append("  主题: ").append(cert.get("subjectDN")).append("\n");
                sb.append("  颁发者: ").append(cert.get("issuerDN")).append("\n");
                sb.append("  有效期: ").append(cert.get("validFrom")).append(" 至 ").append(cert.get("validUntil")).append("\n");
                sb.append("  序列号: ").append(cert.get("serialNumber")).append("\n");
                if (cert.containsKey("subjectAlternativeNames")) {
                    sb.append("  备用名称: ").append(cert.get("subjectAlternativeNames")).append("\n");
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

    public void logError(String message, Throwable cause, int exitCode) {
        logger.error("❌ {}", message);
        if (cause != null && config.isVerbose()) {
            logger.error("详细错误信息:", cause);
        }
    }
}


}

