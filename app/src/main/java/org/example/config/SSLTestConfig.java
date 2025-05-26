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

    @Option(names = {"--client-cert"}, description = "客户端证书文件路径")
    private File clientCertFile;

    @Option(names = {"--client-key"}, description = "客户端私钥文件路径")
    private File clientKeyFile;

    @Option(names = {"--client-key-password"}, description = "客户端私钥密码", interactive = true)
    private String clientKeyPassword;

    @Option(names = {"--client-cert-format"}, description = "客户端证书格式: PEM, DER", defaultValue = "PEM")
    private CertificateFormat clientCertFormat = CertificateFormat.PEM;

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private File outputFile;

    @Option(names = {"--format"}, description = "输出格式: TEXT, JSON, YAML", defaultValue = "TEXT")
    private OutputFormat format = OutputFormat.TEXT;

    @Option(names = {"-v", "--verbose"}, description = "显示详细输出")
    private boolean verbose = false;

    @Option(names = {"--log-cert-details"}, description = "在日志中显示证书详细信息", defaultValue = "true")
    private boolean logCertDetails = true;

    @Option(names = {"-c", "--config"}, description = "配置文件路径 (YAML/JSON)")
    private File configFile;

    @Option(names = {"--check-ocsp"}, description = "是否检查OCSP", defaultValue = "true")
    private boolean checkOCSP = true;

    @Option(names = {"--check-crl"}, description = "是否检查CRL", defaultValue = "true")
    private boolean checkCRL = true;

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
     * Gets the client certificate file.
     * Corresponds to the command-line option(s) {@code --client-cert}.
     * @return The client certificate file, or null if not specified.
     */
    public File getClientCertFile() { return clientCertFile; }

    /**
     * Gets the client private key file.
     * Corresponds to the command-line option(s) {@code --client-key}.
     * @return The client private key file, or null if not specified.
     */
    public File getClientKeyFile() { return clientKeyFile; }

    /**
     * Gets the client private key password.
     * Corresponds to the command-line option(s) {@code --client-key-password}.
     * Typically entered interactively.
     * @return The client private key password, or null if not specified.
     */
    public String getClientKeyPassword() { return clientKeyPassword; }

    /**
     * Gets the client certificate format.
     * Corresponds to the command-line option(s) {@code --client-cert-format}.
     * @return The client certificate format enum value.
     */
    public CertificateFormat getClientCertFormat() { return clientCertFormat; }

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
     * Checks if detailed certificate information should be logged.
     * Corresponds to the command-line option(s) {@code --log-cert-details}.
     * @return True if detailed certificate information should be logged, false otherwise.
     */
    public boolean isLogCertDetails() { return logCertDetails; }

    /**
     * Gets the configuration file path.
     * Corresponds to the command-line option(s) {@code -c, --config}.
     * @return The configuration file path, or null if not specified.
     */
    public File getConfigFile() { return configFile; }

    /**
     * Checks if OCSP checking should be performed.
     * Corresponds to the command-line option(s) {@code --check-ocsp}.
     * @return True if OCSP checking should be performed, false otherwise.
     */
    public boolean isCheckOCSP() { return checkOCSP; }

    /**
     * Checks if CRL checking should be performed.
     * Corresponds to the command-line option(s) {@code --check-crl}.
     * @return True if CRL checking should be performed, false otherwise.
     */
    public boolean isCheckCRL() { return checkCRL; }

    /**
     * Gets the output file path.
     * Corresponds to the command-line option(s) {@code -o, --output}.
     * @return The output file path, or null if not specified.
     */
    public File getOutputFile() { return outputFile; }

    // Setters

    /**
     * Sets the target HTTPS URL to be tested.
     * Corresponds to the positional parameter at index 0.
     * @param url The target URL string.
     */
    public void setUrl(String url) { this.url = url; }

    /**
     * Sets the connection timeout in milliseconds.
     * Corresponds to the command-line option(s) {@code -t, --timeout}.
     * @param connectionTimeout The connection timeout value.
     */
    public void setConnectionTimeout(int connectionTimeout) { this.connectionTimeout = connectionTimeout; }

    /**
     * Sets the read timeout in milliseconds.
     * Corresponds to the command-line option(s) {@code -r, --read-timeout}.
     * @param readTimeout The read timeout value.
     */
    public void setReadTimeout(int readTimeout) { this.readTimeout = readTimeout; }

    /**
     * Sets whether the tool should follow HTTP redirects.
     * Corresponds to the command-line option(s) {@code -f, --follow-redirects}.
     * @param followRedirects True if redirects should be followed, false otherwise.
     */
    public void setFollowRedirects(boolean followRedirects) { this.followRedirects = followRedirects; }

    /**
     * Sets the custom truststore (keystore) file.
     * Corresponds to the command-line option(s) {@code -k, --keystore}.
     * @param keystoreFile The truststore file, or null if not specified.
     */
    public void setKeystoreFile(File keystoreFile) { this.keystoreFile = keystoreFile; }

    /**
     * Sets the password for the custom truststore.
     * Corresponds to the command-line option(s) {@code -p, --keystore-password}.
     * @param keystorePassword The truststore password, or null if not specified.
     */
    public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }

    /**
     * Sets the client certificate file.
     * Corresponds to the command-line option(s) {@code --client-cert}.
     * @param clientCertFile The client certificate file, or null if not specified.
     */
    public void setClientCertFile(File clientCertFile) { this.clientCertFile = clientCertFile; }

    /**
     * Sets the client private key file.
     * Corresponds to the command-line option(s) {@code --client-key}.
     * @param clientKeyFile The client private key file, or null if not specified.
     */
    public void setClientKeyFile(File clientKeyFile) { this.clientKeyFile = clientKeyFile; }

    /**
     * Sets the client private key password.
     * Corresponds to the command-line option(s) {@code --client-key-password}.
     * @param clientKeyPassword The client private key password, or null if not specified.
     */
    public void setClientKeyPassword(String clientKeyPassword) { this.clientKeyPassword = clientKeyPassword; }

    /**
     * Sets the client certificate format.
     * Corresponds to the command-line option(s) {@code --client-cert-format}.
     * @param clientCertFormat The client certificate format enum value.
     */
    public void setClientCertFormat(CertificateFormat clientCertFormat) { this.clientCertFormat = clientCertFormat; }

    /**
     * Sets the output file path.
     * Corresponds to the command-line option(s) {@code -o, --output}.
     * @param outputFile The output file path, or null if not specified.
     */
    public void setOutputFile(File outputFile) { this.outputFile = outputFile; }

    /**
     * Sets the desired output format for the results.
     * Corresponds to the command-line option(s) {@code --format}.
     * @param format The output format enum value.
     */
    public void setFormat(OutputFormat format) { this.format = format; }

    /**
     * Sets whether verbose output is enabled.
     * Corresponds to the command-line option(s) {@code -v, --verbose}.
     * @param verbose True if verbose output is enabled, false otherwise.
     */
    public void setVerbose(boolean verbose) { this.verbose = verbose; }

    /**
     * Sets whether detailed certificate information should be logged.
     * Corresponds to the command-line option(s) {@code --log-cert-details}.
     * @param logCertDetails True if detailed certificate information should be logged, false otherwise.
     */
    public void setLogCertDetails(boolean logCertDetails) { this.logCertDetails = logCertDetails; }

    /**
     * Sets the configuration file path.
     * Corresponds to the command-line option(s) {@code -c, --config}.
     * @param configFile The configuration file path, or null if not specified.
     */
    public void setConfigFile(File configFile) { this.configFile = configFile; }

    /**
     * Sets whether OCSP checking should be performed.
     * Corresponds to the command-line option(s) {@code --check-ocsp}.
     * @param checkOCSP True if OCSP checking should be performed, false otherwise.
     */
    public void setCheckOCSP(boolean checkOCSP) { this.checkOCSP = checkOCSP; }

    /**
     * Sets whether CRL checking should be performed.
     * Corresponds to the command-line option(s) {@code --check-crl}.
     * @param checkCRL True if CRL checking should be performed, false otherwise.
     */
    public void setCheckCRL(boolean checkCRL) { this.checkCRL = checkCRL; }

    public enum OutputFormat {
        /** Plain text format, human-readable. */
        TEXT,
        /** JSON format, machine-readable. */
        JSON,
        /** YAML format, human and machine-readable. */
        YAML
    }

    public enum CertificateFormat {
        PEM, DER
    }
}

