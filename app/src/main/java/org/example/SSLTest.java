package org.example;

import org.example.cert.CertificateValidator;
import org.example.cert.ClientCertificateManager;
import org.example.config.SSLTestConfig;
import org.example.config.SSLTestConfigFile;
import org.example.exception.SSLTestException;
import org.example.output.ResultFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import org.example.model.CertificateDetails;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * Main class for the SSL Test command-line application.
 * This class uses Picocli for command-line argument parsing and orchestrates
 * the SSL/TLS connection testing process, including certificate validation,
 * revocation checking, and hostname verification.
 * It implements {@link Callable} to be executed by Picocli's {@link CommandLine}.
 */
@Command(name = "ssltest", 
        description = "A command-line tool to test SSL/TLS connections, validate certificate chains, " +
                      "check revocation status (OCSP/CRL), and verify hostnames.",
        mixinStandardHelpOptions = true,
        version = "SSLTest 1.0") // Example version
public class SSLTest implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(SSLTest.class);

    // Exit codes constants for application termination status.
    /** Indicates successful execution. */
    private static final int EXIT_SUCCESS = 0;
    /** Indicates invalid command-line arguments were provided. */
    private static final int EXIT_INVALID_ARGS = 1;
    /** Indicates an error occurred during the SSL handshake process. */
    private static final int EXIT_SSL_HANDSHAKE_ERROR = 2;
    /** Indicates a general connection error (e.g., timeout, network issue). */
    private static final int EXIT_CONNECTION_ERROR = 3;
    /** Indicates a failure in certificate validation (trust, expiry, revocation). */
    private static final int EXIT_CERTIFICATE_VALIDATION_ERROR = 4; // As per README
    /** Indicates that hostname verification against the certificate failed. */
    private static final int EXIT_HOSTNAME_VERIFICATION_ERROR = 5;
    /** Indicates an unexpected or unhandled error occurred. */
    private static final int EXIT_UNEXPECTED_ERROR = 99;

    /** Configuration object populated by Picocli with command-line arguments. */
    @CommandLine.Mixin
    private final SSLTestConfig config;

    /** Validator for X.509 certificate chains. */
    private final CertificateValidator certValidator;
    /** Formatter for outputting test results in various formats (TEXT, JSON, YAML). */
    private final ResultFormatter resultFormatter;
    /** Manager for client certificate credentials, used for mTLS. */
    private final ClientCertificateManager clientCertManager;
    /** Map to store the results of the SSL test for output. */
    private final Map<String, Object> result = new HashMap<>();

    /**
     * Default constructor used by Picocli when no arguments are passed to instantiate.
     * Initializes with a default {@link SSLTestConfig}.
     */
    public SSLTest() {
        this(new SSLTestConfig());
    }

    /**
     * Constructor for dependency injection, primarily for testing purposes.
     * Allows injecting a pre-configured {@link SSLTestConfig} and subsequently
     * initializes internal components like {@link CertificateValidator}, 
     * {@link ResultFormatter}, and {@link ClientCertificateManager} based on this configuration.
     *
     * @param config The {@link SSLTestConfig} instance to use. Must not be null.
     */
    public SSLTest(SSLTestConfig config) {
        if (config == null) {
            // Though Picocli usually instantiates with its own config, defensive check for direct use.
            logger.warn("SSLTestConfig was null in constructor. Initializing with a new default SSLTestConfig.");
            this.config = new SSLTestConfig();
        } else {
            this.config = config;
        }
        // Initialize core components with the provided or default configuration
        this.certValidator = new CertificateValidator(this.config.getKeystoreFile(), this.config.getKeystorePassword(), this.config);
        this.resultFormatter = new ResultFormatter(this.config);
        this.clientCertManager = new ClientCertificateManager(this.config);
    }

    /**
     * Main entry point for the application when run from the command line.
     * Executes the Picocli command processing and then terminates with the exit code.
     *
     * @param args Command-line arguments.
     */
    public static void main(String... args) {
        // Create an instance of SSLTest, allowing Picocli to inject/mixin configurations.
        // CommandLine will use the no-arg constructor by default for 'new SSLTest()'.
        int exitCode = new CommandLine(new SSLTest()).execute(args);
        System.exit(exitCode);
    }

    /**
     * The main execution logic when the command is run.
     * This method is called by Picocli after parsing command-line arguments.
     * It orchestrates the SSL test: configuration loading, URL parsing,
     * connection establishment, certificate validation, and result formatting.
     *
     * @return An integer exit code indicating the outcome of the test.
     *         See static EXIT_* constants for specific meanings.
     */
    @Override
    public Integer call() {
        logger.info("Starting SSL test for URL: {}", config.getUrl()); 
        try {
            // Initial URL check from the config object (could be from CLI or default)
            String urlString = config.getUrl();
            if (urlString == null || urlString.trim().isEmpty()) {
                logger.error("URL is required but was not provided or was empty.");
                throw new SSLTestException("URL is required.", EXIT_INVALID_ARGS);
            }
            logger.info("Target URL specified: {}", urlString);


            // Load additional configuration from a file if specified.
            // This can override or supplement command-line arguments.
            if (config.getConfigFile() != null) {
                logger.info("Loading configuration from file: {}", config.getConfigFile().getAbsolutePath());
                try {
                    Map<String, Object> fileConfig = SSLTestConfigFile.loadConfig(config.getConfigFile());
                    SSLTestConfigFile.applyConfig(fileConfig, config); // Updates the 'config' object
                    logger.info("Successfully loaded and applied configuration from {}.", config.getConfigFile().getAbsolutePath());
                    logger.debug("Effective configuration after file load: ConnectionTimeout={}, ReadTimeout={}, OCSP={}, CRL={}", 
                                 config.getConnectionTimeout(), config.getReadTimeout(), config.isCheckOCSP(), config.isCheckCRL());
                } catch (IOException e) {
                    logger.error("Failed to load configuration file '{}': {}", config.getConfigFile().getAbsolutePath(), e.getMessage(), e);
                    throw new SSLTestException("Failed to load configuration file: " + e.getMessage(), EXIT_INVALID_ARGS, e);
                }
            }
            
            // Validate and parse the URL (which might have been updated from the config file)
            URL parsedUrl = parseAndValidateUrl(config.getUrl()); 
            
            // Perform the main SSL connection and validation logic
            testSSLConnection(parsedUrl);
            
            // Output successful results
            logger.info("SSL test completed successfully for URL: {}.", parsedUrl);
            resultFormatter.formatAndOutput(result); // The 'result' map is populated by testSSLConnection and processCertificates
            return EXIT_SUCCESS;
        } catch (SSLTestException e) {
            // Handle known SSLTest specific errors (includes validation, handshake, connection issues)
            logger.error("SSLTestException caught: Message='{}', ExitCode={}", e.getMessage(), e.getExitCode(), e.getCause());
            handleError(e.getMessage(), e.getCause(), e.getExitCode());
            return e.getExitCode();
        } catch (Exception e) {
            // Handle any other unexpected errors during the test execution
            logger.error("Unexpected error during SSL test execution: {}", e.getMessage(), e);
            handleError("Unexpected error: " + e.getMessage(), e, EXIT_UNEXPECTED_ERROR);
            return EXIT_UNEXPECTED_ERROR;
        }
    }

    /**
     * Handles error reporting by logging the error, populating the {@code result} map
     * with error details, and then formatting this error information for output.
     *
     * @param message   The primary error message.
     * @param cause     The underlying {@link Throwable} that caused the error, if any.
     * @param exitCode  The exit code to associate with this error.
     */
    private void handleError(String message, Throwable cause, int exitCode) {
        logger.error("Error handled: '{}', Exit Code: {}. Preparing error output.", message, exitCode);
        if (cause != null) {
            logger.debug("Underlying cause of error: ", cause); // Full stack trace if debug is enabled
        }
        
        result.put("error", message);
        result.put("status", "failed"); // Indicate overall failure in the result map
        if (cause != null) {
            // Include a summary of the cause to avoid deeply nested objects in JSON/YAML if the cause is complex.
            result.put("errorCause", cause.getClass().getName() + (cause.getMessage() != null ? ": " + cause.getMessage() : ""));
        }
        result.put("exitCode", exitCode);
        
        // Ensure resultFormatter is available; it should be unless SSLTest constructor itself failed.
        if (resultFormatter != null) {
            resultFormatter.formatAndOutput(result);
        } else {
            // Fallback critical error reporting if resultFormatter isn't available.
            System.err.println("FATAL: ResultFormatter not initialized. Error: " + message);
            if (cause != null) {
                System.err.println("Cause: " + cause.getMessage());
            }
        }
    }

    /**
     * Parses the given URL string and validates that it uses the HTTPS protocol.
     *
     * @param urlStr The URL string to parse and validate.
     * @return A {@link URL} object if parsing and validation are successful.
     * @throws SSLTestException if the URL is malformed, has an invalid syntax, or does not use HTTPS.
     */
    private URL parseAndValidateUrl(String urlStr) throws SSLTestException {
        logger.debug("Attempting to parse and validate URL: {}", urlStr);
        if (urlStr == null || urlStr.trim().isEmpty()) { // Should be caught by initial check in call() or if config reloads a blank URL
            logger.error("URL is null or empty during parsing stage.");
            throw new SSLTestException("URL became null or empty after config processing.", EXIT_INVALID_ARGS);
        }
        try {
            URI uri = new URI(urlStr); // Use URI for better parsing and scheme validation
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                logger.error("Invalid URL scheme: {}. URL must use HTTPS.", uri.getScheme());
                throw new SSLTestException("URL must use HTTPS protocol. Found: " + uri.getScheme(), EXIT_INVALID_ARGS);
            }
            URL parsedUrl = uri.toURL();
            logger.debug("URL successfully parsed and validated: {}", parsedUrl);
            return parsedUrl;
        } catch (java.net.MalformedURLException e) {
            logger.error("Malformed URL '{}': {}", urlStr, e.getMessage(), e);
            throw new SSLTestException("Invalid URL format: " + urlStr + ". Error: " + e.getMessage(), EXIT_INVALID_ARGS, e);
        } catch (java.net.URISyntaxException e) {
            logger.error("Invalid URL syntax '{}': {}", urlStr, e.getMessage(), e);
            throw new SSLTestException("Invalid URL syntax: " + urlStr + ". Error: " + e.getMessage(), EXIT_INVALID_ARGS, e);
        } catch (Exception e) { // Catch-all for other unexpected parsing issues
            logger.error("Unexpected error parsing URL '{}': {}", urlStr, e.getMessage(), e);
            throw new SSLTestException("Unexpected error parsing URL: " + urlStr + ". Error: " + e.getMessage(), EXIT_INVALID_ARGS, e);
        }
    }

    /**
     * Orchestrates the SSL connection process:
     * <ol>
     *   <li>Sets up an {@link HttpsURLConnection}.</li>
     *   <li>Connects to the server (triggering SSL handshake).</li>
     *   <li>Retrieves connection details (HTTP status, cipher suite).</li>
     *   <li>Retrieves server certificates.</li>
     *   <li>Validates the certificate chain using {@link CertificateValidator}.</li>
     *   <li>Verifies the hostname against the end-entity certificate.</li>
     *   <li>Populates the {@code result} map with all gathered information.</li>
     * </ol>
     * This method throws {@link SSLTestException} for specific failure types,
     * which are then mapped to appropriate exit codes by the {@code call()} method.
     *
     * @param url The {@link URL} to connect to.
     * @throws SSLTestException if any part of the SSL connection, handshake, certificate validation,
     *                          or hostname verification fails.
     */
    private void testSSLConnection(URL url) throws SSLTestException {
        HttpsURLConnection conn = null;
        logger.info("Attempting to establish SSL connection to: {}", url.toString());
        try {
            // Setup connection details (timeouts, redirects, client certs if configured)
            conn = setupConnection(url);
            
            // This initiates the SSL handshake when getting response code or server certificates.
            logger.debug("Getting HTTP response code for {} to trigger handshake.", url.toString());
            int responseCode = conn.getResponseCode();
            String cipherSuite = conn.getCipherSuite(); // Get after successful handshake
            logger.info("Successfully connected to {}. HTTP Status: {}, Cipher Suite: {}", url.toString(), responseCode, cipherSuite);
            
            result.put("httpStatus", responseCode);
            result.put("cipherSuite", cipherSuite);

            // Retrieve and validate server certificates
            logger.debug("Retrieving server certificates from connection to {}.", url.toString());
            Certificate[] serverCerts = conn.getServerCertificates();
            if (serverCerts == null || serverCerts.length == 0) {
                logger.error("No server certificates received from {}.", url.toString());
                throw new SSLTestException("No server certificates received.", EXIT_CERTIFICATE_VALIDATION_ERROR);
            }
            logger.info("Received {} server certificate(s) from {}.", serverCerts.length, url.toString());

            // Validate the certificate chain (includes trust path and revocation status checks)
            List<CertificateDetails> certificateDetailsList = certValidator.validateCertificateChain(serverCerts);
            
            // Validate hostname against the end-entity certificate (first in the chain)
            if (serverCerts[0] instanceof X509Certificate) {
                validateHostname(url, (X509Certificate) serverCerts[0]);
            } else {
                logger.error("End-entity certificate is not an X509Certificate instance for {}.", url.toString());
                throw new SSLTestException("End-entity certificate is not an X509Certificate instance.", EXIT_CERTIFICATE_VALIDATION_ERROR);
            }
            
            // Process and store detailed certificate information for output
            processCertificates(certificateDetailsList);

            logger.info("✅ SSL connection, certificate validation, and hostname verification succeeded for {}.", url.toString());
            result.put("status", "success"); // Indicate overall success in the result map

        } catch (javax.net.ssl.SSLHandshakeException e) {
            logger.error("SSL handshake failed for {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("SSL handshake failed: " + e.getMessage(), EXIT_SSL_HANDSHAKE_ERROR, e);
        } catch (java.security.cert.CertificateException e) {
            // This catches exceptions from certValidator.validateCertificateChain (e.g., trust, revocation)
            logger.error("Certificate validation failed for {}: {}", url.toString(), e.getMessage(), e);
            // The message from CertificateException (e.g., "Certificate ... REVOKED...") is preserved.
            throw new SSLTestException("Certificate validation failed: " + e.getMessage(), EXIT_CERTIFICATE_VALIDATION_ERROR, e);
        } catch (SSLTestException e) { // Re-throw SSLTestExceptions (e.g., from validateHostname or parseAndValidateUrl)
            throw e;
        } catch (IOException e) { // Catch other IOExceptions (e.g., network issues not part of handshake)
            logger.error("IO error during connection to {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("IO error during connection: " + e.getMessage(), EXIT_CONNECTION_ERROR, e);
        } catch (Exception e) { // Catch-all for any other unexpected errors during the process
            logger.error("Unexpected error during SSL connection or validation for {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("Unexpected error during SSL connection or validation: " + e.getMessage(), EXIT_UNEXPECTED_ERROR, e);
        } finally {
            if (conn != null) {
                logger.debug("Disconnecting HttpsURLConnection for {}.", url.toString());
                conn.disconnect();
            }
        }
    }

    /**
     * Sets up an {@link HttpsURLConnection} with configured timeouts, redirect policy,
     * and client certificate (if provided for mTLS).
     *
     * @param url The URL to connect to.
     * @return An {@link HttpsURLConnection} instance, not yet connected.
     * @throws IOException if an I/O error occurs when opening the connection.
     */
    private HttpsURLConnection setupConnection(URL url) throws java.io.IOException {
        logger.info("Setting up connection to {} …", url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(config.getConnectionTimeout());
        conn.setReadTimeout(config.getReadTimeout());
        conn.setInstanceFollowRedirects(config.isFollowRedirects());
        logger.debug("Connection params: ConnectTimeout={}, ReadTimeout={}, FollowRedirects={}", 
                     config.getConnectionTimeout(), config.getReadTimeout(), config.isFollowRedirects());

        // Set up client certificate for mTLS if configured
        try {
            SSLContext clientSslContext = clientCertManager.createSSLContext();
            if (clientSslContext != null) {
                conn.setSSLSocketFactory(clientSslContext.getSocketFactory());
                logger.info("Applied custom SSLSocketFactory for mTLS using client certificate.");
            }
        } catch (Exception e) {
            // Log a warning but don't fail the entire connection setup here,
            // as mTLS might be optional or misconfigured. The connection will proceed without it.
            logger.warn("Failed to set up client certificate for mTLS. Proceeding without client cert. Error: {}", e.getMessage(), e);
        }

        // Note: conn.connect() is called implicitly by methods like getResponseCode() or getServerCertificates().
        // Explicitly calling it here is not strictly necessary but can be done.
        // For this flow, it's called in testSSLConnection before getting response code.
        return conn;
    }

    /**
     * Validates the server's hostname against the provided end-entity certificate.
     * This uses the {@link CertificateValidator#verifyHostname(X509Certificate, String)} method.
     *
     * @param url  The URL containing the hostname to verify.
     * @param cert The end-entity X.509 certificate from the server.
     * @throws SSLTestException if hostname verification fails.
     */
    private void validateHostname( URL url, X509Certificate cert) throws SSLTestException {
        String hostname = url.getHost();
        logger.debug("Validating hostname '{}' against certificate subject: {}", hostname, cert.getSubjectX500Principal().getName());
        try {
            if (!certValidator.verifyHostname(cert, hostname)) {
                logger.warn("Hostname verification failed for host '{}'. Certificate SANs or CN did not match.", hostname);
                throw new SSLTestException("Hostname verification failed for host " + hostname,
                        EXIT_HOSTNAME_VERIFICATION_ERROR);
            }
            logger.info("→ Hostname verification passed for '{}'.", hostname);
            result.put("hostnameVerified", true);
        } catch (Exception e) { // Catch any unexpected error during hostname verification
            logger.error("Error during hostname verification for '{}': {}", hostname, e.getMessage(), e);
            throw new SSLTestException("Error during hostname verification: " + e.getMessage(), EXIT_HOSTNAME_VERIFICATION_ERROR, e);
        }
    }

    /**
     * Processes the list of {@link CertificateDetails} (obtained from {@link CertificateValidator})
     * and prepares them for inclusion in the main {@code result} map for final output.
     * Each {@code CertificateDetails} object is converted into a map of its properties.
     *
     * @param certDetailsList A list of {@link CertificateDetails} representing the validated certificate chain.
     */
    private void processCertificates(List<CertificateDetails> certDetailsList) {
        logger.debug("Processing {} certificate(s) for output.", certDetailsList.size());
        List<Map<String, Object>> outputCertList = new ArrayList<>();
        for (CertificateDetails details : certDetailsList) {
            Map<String, Object> certMap = new HashMap<>();
            certMap.put("subjectDN", details.getSubjectDN());
            certMap.put("issuerDN", details.getIssuerDN());
            certMap.put("version", details.getVersion());
            certMap.put("serialNumber", details.getSerialNumber());
            certMap.put("validFrom", details.getValidFrom() != null ? DATE_FORMATTER.format(details.getValidFrom().toInstant()) : "N/A");
            certMap.put("validUntil", details.getValidUntil() != null ? DATE_FORMATTER.format(details.getValidUntil().toInstant()) : "N/A");
            certMap.put("signatureAlgorithm", details.getSignatureAlgorithm());
            certMap.put("publicKeyAlgorithm", details.getPublicKeyAlgorithm());
            certMap.put("subjectAlternativeNames", details.getSubjectAlternativeNames()); // This is already a Map<String,String>
            certMap.put("selfSigned", details.isSelfSigned());
            certMap.put("expired", details.isExpired());
            certMap.put("notYetValid", details.isNotYetValid());
            certMap.put("trustStatus", details.getTrustStatus() != null ? details.getTrustStatus().name() : "UNKNOWN");
            certMap.put("revocationStatus", details.getRevocationStatus() != null ? details.getRevocationStatus().name() : "UNKNOWN");
            
            if (details.getOcspResponderUrl() != null && !details.getOcspResponderUrl().isEmpty()) {
                certMap.put("ocspResponderUrl", details.getOcspResponderUrl());
            }
            if (details.getCrlDistributionPoints() != null && !details.getCrlDistributionPoints().isEmpty()) {
                certMap.put("crlDistributionPoints", details.getCrlDistributionPoints());
            }
            if (details.getFailureReason() != null && !details.getFailureReason().isEmpty()) {
                certMap.put("failureReason", details.getFailureReason());
            }
            outputCertList.add(certMap);
        }
        result.put("certificateChain", outputCertList);
        logger.info("→ Processed and stored details for {} certificate(s).", certDetailsList.size());
    }
}
