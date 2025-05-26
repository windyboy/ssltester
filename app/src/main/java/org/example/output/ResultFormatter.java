package org.example.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.example.config.SSLTestConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

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
                default: // Default to TEXT if somehow null or another value
                    output = formatMapAsText(result, 0);
                    break;
            }

            if (config.getOutputFile() != null) {
                try (PrintWriter writer = new PrintWriter(new FileWriter(config.getOutputFile()))) {
                    writer.print(output); // Use print to avoid extra newline for text format if it ends with one
                }
                logger.info("Results written to: {}", config.getOutputFile().getAbsolutePath());
            } else {
                System.out.print(output); // Use print for consistency
            }
        } catch (Exception e) {
            logger.error("Error writing results: {}", e.getMessage(), e); // English error message
        }
    }

    /**
     * Formats a map into a human-readable string representation.
     * Handles nested maps and lists for clear textual output.
     *
     * @param map The map to format.
     * @param indentLevel The current indentation level for pretty-printing.
     * @return A string representation of the map.
     */
    private String formatMapAsText(Map<String, Object> map, int indentLevel) {
        StringBuilder sb = new StringBuilder();
        String indent = "  ".repeat(indentLevel); // Two spaces per indent level

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sb.append(indent).append(entry.getKey()).append(": ");
            Object value = entry.getValue();

            if (value instanceof Map) {
                //noinspection unchecked
                sb.append("\n").append(formatMapAsText((Map<String, Object>) value, indentLevel + 1));
            } else if (value instanceof List) {
                //noinspection unchecked
                List<?> listValue = (List<?>) value;
                if (listValue.isEmpty()) {
                    sb.append("[]\n");
                } else {
                    sb.append("\n");
                    for (int i = 0; i < listValue.size(); i++) {
                        Object item = listValue.get(i);
                        sb.append(indent).append("  - "); // Indent list items further
                        if (item instanceof Map) {
                            //noinspection unchecked
                            sb.append("\n").append(formatMapAsText((Map<String, Object>) item, indentLevel + 2));
                        } else {
                            sb.append(item != null ? item.toString() : "null").append("\n");
                        }
                    }
                }
            } else if (value instanceof String && ((String) value).contains("\n")) {
                // Handle multi-line strings
                sb.append("\n");
                String[] lines = ((String) value).split("\n");
                for (String line : lines) {
                    sb.append(indent).append("  ").append(line).append("\n");
                }
            }
             else {
                sb.append(value != null ? value.toString() : "null").append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * Logs an error message. If verbose mode is enabled in the configuration,
     * it also logs the full stack trace of the associated exception.
     *
     * @param message The primary error message to log.
     * @param cause The Throwable (exception) that caused the error. Can be null.
     * @param exitCode The exit code associated with this error. (Currently not used in this method but good for context)
     */
    public void logError(String message, Throwable cause, int exitCode) {
        logger.error("❌ {}", message);
        if (cause != null && config.isVerbose()) {
            logger.error("Detailed error information:", cause);
        }
    }
}