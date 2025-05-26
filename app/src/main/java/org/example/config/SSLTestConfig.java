package org.example.config;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;

/**
 * Holds configuration parameters for the SSL/TLS test tool.
 * These parameters are populated by Picocli from command-line arguments.
 * Each field corresponds to a command-line option or positional parameter.
 */
public class SSLTestConfig {
    @Parameters(index = "0", description = "要测试的HTTPS URL")
    private String url;

    @Option(names = {"-t", "--timeout"}, description = "连接超时时间(毫秒)")
    private int connectionTimeout = 5000;

    @Option(names = {"-r", "--read-timeout"}, description = "读取超时时间(毫秒)")
    private int readTimeout = 5000;

    @Option(names = {"-f", "--follow-redirects"}, description = "是否跟随重定向")
    private boolean followRedirects = false;

    @Option(names = {"-k", "--keystore"}, description = "信任库文件路径")
    private File keystoreFile;

    @Option(names = {"-p", "--keystore-password"}, description = "信任库密码", interactive = true)
    private String keystorePassword;

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private File outputFile;

    @Option(names = {"--format"}, description = "输出格式: TEXT, JSON, YAML", defaultValue = "TEXT")
    private OutputFormat format = OutputFormat.TEXT;

    @Option(names = {"-v", "--verbose"}, description = "显示详细输出")
    private boolean verbose = false;

    // Getters

    /**
     * Gets the target HTTPS URL to be tested.
     * Corresponds to the positional parameter at index 0.
     * @return The target URL string.
     */
    public String getUrl() { return url; }

    /**
     * Gets the connection timeout in milliseconds.
     * Corresponds to the command-line option(s) {@code -t, --timeout}.
     * Default value is 5000ms.
     * @return The connection timeout value.
     */
    public int getConnectionTimeout() { return connectionTimeout; }

    /**
     * Gets the read timeout in milliseconds.
     * Corresponds to the command-line option(s) {@code -r, --read-timeout}.
     * Default value is 5000ms.
     * @return The read timeout value.
     */
    public int getReadTimeout() { return readTimeout; }

    /**
     * Checks if the tool should follow HTTP redirects.
     * Corresponds to the command-line option(s) {@code -f, --follow-redirects}.
     * Default value is false.
     * @return True if redirects should be followed, false otherwise.
     */
    public boolean isFollowRedirects() { return followRedirects; }

    /**
     * Gets the custom truststore (keystore) file.
     * Corresponds to the command-line option(s) {@code -k, --keystore}.
     * Default is null (system default truststore is used).
     * @return The truststore file, or null if not specified.
     */
    public File getKeystoreFile() { return keystoreFile; }

    /**
     * Gets the password for the custom truststore.
     * Corresponds to the command-line option(s) {@code -p, --keystore-password}.
     * Typically entered interactively.
     * @return The truststore password, or null if not specified.
     */
    public String getKeystorePassword() { return keystorePassword; }

    /**
     * Gets the file path for saving the output.
     * Corresponds to the command-line option(s) {@code -o, --output}.
     * Default is null (output to standard out).
     * @return The output file, or null if not specified.
     */
    public File getOutputFile() { return outputFile; }

    /**
     * Gets the desired output format for the results.
     * Corresponds to the command-line option(s) {@code --format}.
     * Default value is {@link OutputFormat#TEXT}.
     * @return The output format enum value.
     */
    public OutputFormat getFormat() { return format; }

    /**
     * Checks if verbose output is enabled.
     * Corresponds to the command-line option(s) {@code -v, --verbose}.
     * Default value is false.
     * @return True if verbose output is enabled, false otherwise.
     */
    public boolean isVerbose() { return verbose; }

    /**
     * Defines the available output formats for the test results.
     */
    public enum OutputFormat {
        /** Plain text format, human-readable. */
        TEXT,
        /** JSON format, machine-readable. */
        JSON,
        /** YAML format, human and machine-readable. */
        YAML
    }
}