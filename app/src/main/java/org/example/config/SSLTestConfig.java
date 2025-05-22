package org.example.config;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;

/**
 * Configuration class for the SSL Test application.
 * Holds all command-line parameters and options, managed by Picocli.
 * Also provides getters and setters for these properties, allowing them
 * to be updated programmatically (e.g., from a configuration file).
 */
public class SSLTestConfig {
    /** The HTTPS URL to be tested. This is a mandatory parameter. */
    @Parameters(index = "0", description = "The HTTPS URL to test (e.g., https://example.com).")
    private String url;

    /** Connection timeout in milliseconds. Default is 5000ms. */
    @Option(names = {"-t", "--timeout"}, description = "Connection timeout in milliseconds. Default: ${DEFAULT-VALUE}.")
    private int connectionTimeout = 5000;

    /** Read timeout in milliseconds. Default is 5000ms. */
    @Option(names = {"-r", "--read-timeout"}, description = "Read timeout in milliseconds. Default: ${DEFAULT-VALUE}.")
    private int readTimeout = 5000;

    /** Flag to determine whether to follow HTTP redirects. Default is false. */
    @Option(names = {"-f", "--follow-redirects"}, description = "Follow HTTP redirects. Default: ${DEFAULT-VALUE}.")
    private boolean followRedirects = false;

    /** Path to a custom truststore (keystore) file. If not provided, system default truststore is used. */
    @Option(names = {"-k", "--keystore"}, description = "Path to a custom truststore (keystore) file.")
    private File keystoreFile;

    /** Password for the custom truststore file. Will be prompted if not provided and keystore is set. */
    @Option(names = {"-p", "--keystore-password"}, description = "Password for the custom truststore. Interactive prompt if not set.", interactive = true)
    private String keystorePassword;

    /** Path to the client certificate file (e.g., for mutual TLS authentication). */
    @Option(names = {"--client-cert"}, description = "Path to the client certificate file (for mTLS).")
    private File clientCertFile;

    /** Path to the client private key file (e.g., for mutual TLS authentication). */
    @Option(names = {"--client-key"}, description = "Path to the client private key file (for mTLS).")
    private File clientKeyFile;

    /** Password for the client private key file. Will be prompted if not provided and client key is set. */
    @Option(names = {"--client-key-password"}, description = "Password for the client private key. Interactive prompt if not set.", interactive = true)
    private String clientKeyPassword;

    /** Format of the client certificate and key. Default is PEM. */
    @Option(names = {"--client-cert-format"}, description = "Client certificate format: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.")
    private CertificateFormat clientCertFormat = CertificateFormat.PEM;

    /** Path to an output file where the results will be written. If not set, results are printed to standard output. */
    @Option(names = {"-o", "--output"}, description = "Path to an output file for the results.")
    private File outputFile;

    /** Format for the output results. Default is TEXT. */
    @Option(names = {"--format"}, description = "Output format: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.")
    private OutputFormat format = OutputFormat.TEXT;

    /** Flag to enable verbose logging output. Default is false. */
    @Option(names = {"-v", "--verbose"}, description = "Enable verbose logging output. Default: ${DEFAULT-VALUE}.")
    private boolean verbose = false;

    /** Flag to control logging of detailed certificate information. Default is true. */
    @Option(names = {"--log-cert-details"}, description = "Log detailed certificate information. Default: ${DEFAULT-VALUE}.")
    private boolean logCertDetails = true;

    /** Path to a configuration file (YAML or JSON) that can provide default values for these options. */
    @Option(names = {"-c", "--config"}, description = "Configuration file path (YAML/JSON) for default values.")
    private File configFile;

    /** Flag to enable OCSP (Online Certificate Status Protocol) checking. Default is true. */
    @Option(names = {"--check-ocsp"}, description = "Enable OCSP revocation checking. Default: ${DEFAULT-VALUE}.")
    private boolean checkOCSP = true;

    /** Flag to enable CRL (Certificate Revocation List) checking. Default is true. */
    @Option(names = {"--check-crl"}, description = "Enable CRL revocation checking. Default: ${DEFAULT-VALUE}.")
    private boolean checkCRL = true;

    // Getters
    /** @return The HTTPS URL to be tested. */
    public String getUrl() { return url; }
    /** @return The connection timeout in milliseconds. */
    public int getConnectionTimeout() { return connectionTimeout; }
    /** @return The read timeout in milliseconds. */
    public int getReadTimeout() { return readTimeout; }
    /** @return True if HTTP redirects should be followed, false otherwise. */
    public boolean isFollowRedirects() { return followRedirects; }
    /** @return The custom truststore file, or null if not set. */
    public File getKeystoreFile() { return keystoreFile; }
    /** @return The password for the custom truststore. */
    public String getKeystorePassword() { return keystorePassword; }
    /** @return The client certificate file for mTLS, or null if not set. */
    public File getClientCertFile() { return clientCertFile; }
    /** @return The client private key file for mTLS, or null if not set. */
    public File getClientKeyFile() { return clientKeyFile; }
    /** @return The password for the client private key. */
    public String getClientKeyPassword() { return clientKeyPassword; }
    /** @return The format of the client certificate (PEM or DER). */
    public CertificateFormat getClientCertFormat() { return clientCertFormat; }
    /** @return The output file for results, or null to use standard output. */
    public File getOutputFile() { return outputFile; }
    /** @return The desired output format (TEXT, JSON, or YAML). */
    public OutputFormat getFormat() { return format; }
    /** @return True if verbose logging is enabled, false otherwise. */
    public boolean isVerbose() { return verbose; }
    /** @return True if detailed certificate logging is enabled. */
    public boolean isLogCertDetails() { return logCertDetails; }
    /** @return The configuration file, or null if not set. */
    public File getConfigFile() { return configFile; }
    /** @return True if OCSP checking is enabled. */
    public boolean isCheckOCSP() { return checkOCSP; }
    /** @return True if CRL checking is enabled. */
    public boolean isCheckCRL() { return checkCRL; }

    // Setters
    /** @param url The HTTPS URL to be tested. */
    public void setUrl(String url) { this.url = url; }
    /** @param connectionTimeout The connection timeout in milliseconds. */
    public void setConnectionTimeout(int connectionTimeout) { this.connectionTimeout = connectionTimeout; }
    /** @param readTimeout The read timeout in milliseconds. */
    public void setReadTimeout(int readTimeout) { this.readTimeout = readTimeout; }
    /** @param followRedirects True to follow HTTP redirects, false otherwise. */
    public void setFollowRedirects(boolean followRedirects) { this.followRedirects = followRedirects; }
    /** @param keystoreFile The custom truststore file. */
    public void setKeystoreFile(File keystoreFile) { this.keystoreFile = keystoreFile; }
    /** @param keystorePassword The password for the custom truststore. */
    public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
    /** @param clientCertFile The client certificate file for mTLS. */
    public void setClientCertFile(File clientCertFile) { this.clientCertFile = clientCertFile; }
    /** @param clientKeyFile The client private key file for mTLS. */
    public void setClientKeyFile(File clientKeyFile) { this.clientKeyFile = clientKeyFile; }
    /** @param clientKeyPassword The password for the client private key. */
    public void setClientKeyPassword(String clientKeyPassword) { this.clientKeyPassword = clientKeyPassword; }
    /** @param clientCertFormat The format of the client certificate. */
    public void setClientCertFormat(CertificateFormat clientCertFormat) { this.clientCertFormat = clientCertFormat; }
    /** @param outputFile The output file for results. */
    public void setOutputFile(File outputFile) { this.outputFile = outputFile; }
    /** @param format The desired output format. */
    public void setFormat(OutputFormat format) { this.format = format; }
    /** @param verbose True to enable verbose logging. */
    public void setVerbose(boolean verbose) { this.verbose = verbose; }
    /** @param logCertDetails True to enable detailed certificate logging. */
    public void setLogCertDetails(boolean logCertDetails) { this.logCertDetails = logCertDetails; }
    /** @param configFile The configuration file. */
    public void setConfigFile(File configFile) { this.configFile = configFile; }
    /** @param checkOCSP True to enable OCSP checking. */
    public void setCheckOCSP(boolean checkOCSP) { this.checkOCSP = checkOCSP; }
    /** @param checkCRL True to enable CRL checking. */
    public void setCheckCRL(boolean checkCRL) { this.checkCRL = checkCRL; }

    /**
     * Defines the possible output formats for the test results.
     */
    public enum OutputFormat {
        /** Plain text format, human-readable. */
        TEXT,
        /** JSON format, machine-readable. */
        JSON,
        /** YAML format, human and machine-readable. */
        YAML
    }

    /**
     * Defines the supported formats for client certificates and keys.
     */
    public enum CertificateFormat {
        /** PEM (Privacy Enhanced Mail) format. */
        PEM,
        /** DER (Distinguished Encoding Rules) format, a binary ASN.1 encoding. */
        DER
    }
}

