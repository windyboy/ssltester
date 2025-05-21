package org.example.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.example.config.SSLTestConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

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
                    output = formatTextOutput(result);
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

