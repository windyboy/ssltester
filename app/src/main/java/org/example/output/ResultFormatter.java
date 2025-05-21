package org.example.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.example.config.SSLTestConfig;
import org.example.ssl.SSLConnectionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
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
        for (Map.Entry<String, Object> entry : result.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof Map[]) {
                // 处理 Map 数组（例如证书信息）
                sb.append(key).append(":\n");
                Map<?, ?>[] mapArray = (Map<?, ?>[]) value;
                for (int i = 0; i < mapArray.length; i++) {
                    sb.append("  [").append(i + 1).append("]:\n");
                    formatMapValue(sb, mapArray[i], 4);
                }
            } else if (value instanceof Map) {
                // 处理单个 Map
                sb.append(key).append(":\n");
                formatMapValue(sb, (Map<?, ?>) value, 2);
            } else if (value instanceof Object[]) {
                // 处理其他类型的数组
                sb.append(key).append(": ");
                Object[] array = (Object[]) value;
                if (array.length > 0) {
                    sb.append("[");
                    for (int i = 0; i < array.length; i++) {
                        sb.append(array[i]);
                        if (i < array.length - 1) {
                            sb.append(", ");
                        }
                    }
                    sb.append("]");
                } else {
                    sb.append("[]");
                }
                sb.append("\n");
            } else {
                // 处理简单值
                sb.append(key).append(": ").append(value).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * 格式化 Map 内容，带缩进
     */
    private void formatMapValue(StringBuilder sb, Map<?, ?> map, int indent) {
        String indentStr = " ".repeat(indent);
        for (Map.Entry<?, ?> subEntry : map.entrySet()) {
            Object subValue = subEntry.getValue();
            if (subValue instanceof Map) {
                sb.append(indentStr).append(subEntry.getKey()).append(":\n");
                formatMapValue(sb, (Map<?, ?>) subValue, indent + 2);
            } else if (subValue instanceof Object[]) {
                sb.append(indentStr).append(subEntry.getKey()).append(": ");
                Object[] array = (Object[]) subValue;
                if (array.length > 0) {
                    sb.append("[");
                    for (int i = 0; i < array.length; i++) {
                        sb.append(array[i]);
                        if (i < array.length - 1) {
                            sb.append(", ");
                        }
                    }
                    sb.append("]");
                } else {
                    sb.append("[]");
                }
                sb.append("\n");
            } else {
                sb.append(indentStr).append(subEntry.getKey()).append(": ").append(subValue).append("\n");
            }
        }
    }

    public void logError(String message, Throwable cause, int exitCode) {
        logger.error("❌ {}", message);
        if (cause != null && config.isVerbose()) {
            logger.error("详细错误信息:", cause);
        }
    }
}


}

