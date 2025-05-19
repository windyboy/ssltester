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
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
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