package org.example;

import org.example.cert.CertificateValidator;
import org.example.config.SSLTestConfig;
import org.example.exception.SSLTestException;
import org.example.util.SecurityStrengthAnalyzer;
import org.example.output.ResultFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * A command-line tool (using Picocli) for testing SSL/TLS connections to a given HTTPS URL.
 * Key functionalities include:
 * <ul>
 *   <li>Establishing an HTTPS connection to the specified URL.</li>
 *   <li>Validating the server's certificate chain against a truststore (system default or custom).</li>
 *   <li>Performing hostname verification (matching hostname against SANs/CN in the certificate).</li>
 *   <li>Requesting OCSP stapling by setting relevant system/security properties.</li>
 *   <li>Assessing and reporting the strength of the negotiated TLS protocol and cipher suite.</li>
 *   <li>Extracting and displaying detailed information about the server's certificates.</li>
 *   <li>Providing results in various formats (TEXT, JSON, YAML).</li>
 * </ul>
 */
@Command(name = "ssltest",
        description = "SSL/TLS Test Tool - Validates HTTPS connections, checks certificate chains, and assesses security configurations.",
        mixinStandardHelpOptions = true)
public class SSLTest implements Callable<Integer> {
    /**
     * SLF4J Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(SSLTest.class);

    // Exit codes
    /** Exit code for successful execution. */
    private static final int EXIT_SUCCESS = 0;
    /** Exit code for invalid command-line arguments. */
    private static final int EXIT_INVALID_ARGS = 1;
    /** Exit code for SSL handshake errors. */
    private static final int EXIT_SSL_HANDSHAKE_ERROR = 2;
    /** Exit code for general connection errors (post-handshake). */
    private static final int EXIT_CONNECTION_ERROR = 3;
    /** Exit code for hostname verification failures. */
    private static final int EXIT_HOSTNAME_VERIFICATION_ERROR = 5;
    /** Exit code for unexpected or unhandled errors. */
    private static final int EXIT_UNEXPECTED_ERROR = 99;

    /**
     * Configuration object populated by Picocli with command-line arguments.
     */
    @CommandLine.Mixin
    private final SSLTestConfig config = new SSLTestConfig();
    /**
     * Validator for SSL/TLS certificates.
     */
    private final CertificateValidator certValidator;
    /**
     * Formatter for outputting test results.
     */
    private final ResultFormatter resultFormatter;
    /**
     * Map used to store all test results before formatting and output.
     * Keys are descriptive strings (e.g., "httpStatus", "cipherSuite"), and values are the corresponding test results.
     */
    private final Map<String, Object> result = new HashMap<>();

    /**
     * Constructs an SSLTest instance.
     * Initializes the {@link CertificateValidator} and {@link ResultFormatter} using the
     * command-line configuration.
     */
    public SSLTest() {
        this.certValidator = new CertificateValidator(config.getKeystoreFile(), config.getKeystorePassword());
        this.resultFormatter = new ResultFormatter(config);
    }

    /**
     * Main entry point for the SSLTest command-line application.
     *
     * @param args Command-line arguments.
     */
    public static void main(String... args) {
        int exitCode = new CommandLine(new SSLTest()).execute(args);
        System.exit(exitCode);
    }

    /**
     * Main execution method called by Picocli when the command is run.
     * It orchestrates the SSL/TLS test by:
     * <ol>
     *   <li>Setting up system/security properties to enable OCSP stapling requests.</li>
     *   <li>Parsing and validating the target URL.</li>
     *   <li>Executing the main test logic via {@link #testSSLConnection(URL)}.</li>
     *   <li>Formatting and outputting the collected results.</li>
     *   <li>Handling any {@link SSLTestException} or other exceptions that occur.</li>
     *   <li>Restoring original system/security properties in a finally block.</li>
     * </ol>
     *
     * @return The exit code for the application.
     */
    @Override
    public Integer call() {
        String originalEnableStatusRequestExtension = null;
        String originalOcspEnable = null;
        try {
            // Store original values and set new values for OCSP stapling
            originalEnableStatusRequestExtension = System.getProperty("jdk.tls.client.enableStatusRequestExtension");
            originalOcspEnable = java.security.Security.getProperty("ocsp.enable");

            System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true");
            java.security.Security.setProperty("ocsp.enable", "true");
            logger.debug("Set jdk.tls.client.enableStatusRequestExtension=true, ocsp.enable=true");

            if (config.getUrl() == null || config.getUrl().trim().isEmpty()) {
                throw new SSLTestException("URL is required", EXIT_INVALID_ARGS);
            }
            
            URL parsedUrl = parseAndValidateUrl(config.getUrl());
            testSSLConnection(parsedUrl);
            resultFormatter.formatAndOutput(result);
            return EXIT_SUCCESS;
        } catch (SSLTestException e) {
            handleError(e.getMessage(), e.getCause(), e.getExitCode());
            return e.getExitCode();
        } catch (Exception e) {
            handleError("Unexpected error: " + e.getMessage(), e, EXIT_UNEXPECTED_ERROR);
            return EXIT_UNEXPECTED_ERROR;
        } finally {
            // Restore original property values
            logger.debug("Restoring original OCSP properties...");
            if (originalEnableStatusRequestExtension != null) {
                System.setProperty("jdk.tls.client.enableStatusRequestExtension", originalEnableStatusRequestExtension);
            } else {
                System.clearProperty("jdk.tls.client.enableStatusRequestExtension");
            }
            if (originalOcspEnable != null) {
                java.security.Security.setProperty("ocsp.enable", originalOcspEnable);
            } else {
                // Security.getProperty returns null if not set, removing it might not be standard
                // For ocsp.enable, if it was null, it means it was relying on the default.
                // Re-setting to "false" or an empty string might be an option if "null" isn't directly settable.
                // However, standard practice is to remove if it wasn't there or restore the exact previous value.
                // java.security.Security properties are not cleared with a simple "clearProperty" like system properties.
                // We'll restore to original or assume if it was null, it should remain unset (or default).
                // For this context, if originalOcspEnable was null, we assume it should go back to its default behavior.
                // The most straightforward way is to set it to "false" if it was null, to ensure it's not "true".
                // However, the property might not exist, in which case setting it to "false" changes state.
                // Let's stick to restoring if it was set, otherwise do nothing (it will take its default).
                // If it was null, the default is false, so explicitly setting to false isn't usually needed.
                // For this specific case, if originalOcspEnable is null, we don't need to do anything to "remove" it.
                // The Security class doesn't have a direct removeProperty method like System.clearProperty.
                 if (originalOcspEnable == null) {
                    // To be safe and ensure it's not "true" if it wasn't set before.
                    // However, this changes the state if it was truly absent.
                    // A common approach is to set it to the default value, which is "false".
                    java.security.Security.setProperty("ocsp.enable", "false"); 
                 }
            }
            logger.debug("Restored OCSP properties to their original values.");
        }
    }

    /**
     * Handles errors by logging them and preparing error information for output.
     * It populates the {@code result} map with error details which are then formatted
     * and displayed by the {@link ResultFormatter}.
     *
     * @param message The primary error message.
     * @param cause The underlying exception that caused the error, if any.
     * @param exitCode The exit code to be associated with this error.
     */
    private void handleError(String message, Throwable cause, int exitCode) {
        resultFormatter.logError(message, cause, exitCode);
        result.put("error", message);
        if (cause != null) {
            result.put("errorCause", cause.getMessage());
        }
        result.put("exitCode", exitCode);
        resultFormatter.formatAndOutput(result);
    }

    /**
     * Parses the input URL string and validates that it uses the HTTPS protocol.
     *
     * @param urlStr The URL string to parse and validate.
     * @return A {@link URL} object if the URL is valid and uses HTTPS.
     * @throws SSLTestException If the URL is malformed or does not use the HTTPS protocol.
     */
    private URL parseAndValidateUrl(String urlStr) throws SSLTestException {
        try {
            URL url = new URI(urlStr).toURL();
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                throw new SSLTestException("URL must use HTTPS protocol", EXIT_INVALID_ARGS);
            }
            return url;
        } catch (Exception e) {
            throw new SSLTestException("Invalid URL: " + e.getMessage(), EXIT_INVALID_ARGS, e);
        }
    }

    /**
     * Orchestrates the SSL/TLS connection test to the specified URL.
     * This method performs the following steps:
     * <ol>
     *   <li>Sets up an {@link HttpsURLConnection}.</li>
     *   <li>Connects to the server and retrieves HTTP status and cipher suite.</li>
     *   <li>Determines the key exchange authentication type from the cipher suite.</li>
     *   <li>Retrieves and validates the server's certificate chain using {@link CertificateValidator#validateCertificateChain(Certificate[], String)}.</li>
     *   <li>Performs hostname verification and TLS/cipher strength analysis via {@link #validateHostname(HttpsURLConnection, URL, X509Certificate)}.</li>
     *   <li>Processes and stores detailed information about each certificate in the chain using {@link #processCertificates(X509Certificate[])}.</li>
     *   <li>Stores all results in the {@code result} map.</li>
     * </ol>
     *
     * @param url The target URL for the SSL/TLS connection test.
     * @throws Exception If any critical error occurs during the connection or validation process.
     */
    private void testSSLConnection(URL url) throws Exception {
        HttpsURLConnection conn = null;
        try {
            conn = setupConnection(url);
            int responseCode = conn.getResponseCode();
            String cipherSuite = conn.getCipherSuite();
            
            logger.info("→ HTTP Status  : {}", responseCode);
            logger.info("→ Cipher Suite : {}", cipherSuite);
            
            result.put("httpStatus", responseCode);
            result.put("cipherSuite", cipherSuite);

            // Determine keyExchangeAuthType from cipher suite
            String keyExchangeAuthType;
            String upperCipherSuite = cipherSuite.toUpperCase();
            if (upperCipherSuite.contains("RSA") && !upperCipherSuite.contains("ECDSA")) {
                keyExchangeAuthType = "RSA";
            } else if (upperCipherSuite.contains("DSS")) {
                keyExchangeAuthType = "DSA";
            } else if (upperCipherSuite.contains("ECDSA")) {
                keyExchangeAuthType = "EC"; 
            } else if (upperCipherSuite.contains("_DH_ANON_")) {
                 keyExchangeAuthType = "DH"; 
            } else {
                logger.warn("Could not reliably determine certificate authType from cipher suite: {}. Validation will proceed without a specific authType, relying on TrustManager defaults.", cipherSuite);
                keyExchangeAuthType = "RSA"; // Defaulting to RSA with a warning
                logger.warn("Defaulting authType to 'RSA' for cipher suite: {}", cipherSuite);
            }

            if (keyExchangeAuthType == null || keyExchangeAuthType.isEmpty()){
                 throw new SSLTestException("Unable to determine authType for certificate validation from cipher: " + cipherSuite, EXIT_UNEXPECTED_ERROR); 
            }
            logger.info("→ AuthType for cert validation: {}", keyExchangeAuthType);
            result.put("keyExchangeAuthType", keyExchangeAuthType);


            Certificate[] certs = conn.getServerCertificates();
            X509Certificate[] x509Certs = certValidator.validateCertificateChain(certs, keyExchangeAuthType);
            validateHostname(conn, url, x509Certs[0]);
            processCertificates(x509Certs);

            logger.info("✅ SSL handshake and HTTP request succeeded.");
            result.put("status", "success");
            result.put("ocspStaplingRequested", true); // Report that OCSP stapling was requested
        } catch (javax.net.ssl.SSLHandshakeException e) {
            throw new SSLTestException("SSL handshake failed: " + e.getMessage(), EXIT_SSL_HANDSHAKE_ERROR, e);
        } catch (Exception e) {
            throw new SSLTestException("Error during request: " + e.getMessage(), EXIT_CONNECTION_ERROR, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Sets up and opens an {@link HttpsURLConnection} to the specified URL.
     * Configures connection timeout, read timeout, and redirect following based on {@link SSLTestConfig}.
     *
     * @param url The URL to connect to.
     * @return An active {@link HttpsURLConnection} to the URL.
     * @throws java.io.IOException If an I/O error occurs when opening the connection.
     */
    private HttpsURLConnection setupConnection(URL url) throws java.io.IOException {
        logger.info("Connecting to {} …", url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(config.getConnectionTimeout());
        conn.setReadTimeout(config.getReadTimeout());
        conn.setInstanceFollowRedirects(config.isFollowRedirects());
        conn.connect();
        return conn;
    }

    private void validateHostname(HttpsURLConnection conn, URL url, X509Certificate cert) throws SSLTestException {
        try {
            Optional<SSLSession> sessionOpt = conn.getSSLSession();
            if (sessionOpt.isEmpty()) {
                throw new SSLTestException("SSL session not available", EXIT_SSL_HANDSHAKE_ERROR);
            }
            SSLSession session = sessionOpt.get();

            // Analyze TLS Protocol and Cipher Suite Strength
            String protocol = session.getProtocol();
            result.put("tlsProtocol", protocol);
            logger.info("→ TLS Protocol : {}", protocol);

            String protocolStrength = SecurityStrengthAnalyzer.analyzeProtocol(protocol);
            String cipherSuiteName = (String) result.get("cipherSuite"); // Already fetched in testSSLConnection
            String cipherStrength = SecurityStrengthAnalyzer.analyzeCipherSuite(cipherSuiteName);

            result.put("tlsProtocolStrength", protocolStrength);
            result.put("cipherSuiteStrength", cipherStrength);
            logger.info("→ TLS Protocol Strength: {}", protocolStrength);
            logger.info("→ Cipher Suite Strength: {}", cipherStrength);

            if (protocolStrength.equals("WEAK") || cipherStrength.equals("WEAK")) {
                result.put("securityWarning", "Weak TLS protocol or cipher suite detected. Review details.");
                logger.warn("SECURITY WARNING: Weak TLS protocol or cipher suite detected.");
            }

            String hostname = url.getHost();
            if (!certValidator.verifyHostname(cert, hostname)) {
                throw new SSLTestException("Hostname verification failed for host " + hostname,
                        EXIT_HOSTNAME_VERIFICATION_ERROR);
            }
            logger.info("→ Hostname verification passed");
            result.put("hostnameVerified", true);
        } catch (Exception e) {
            throw new SSLTestException("Hostname validation error: " + e.getMessage(), EXIT_HOSTNAME_VERIFICATION_ERROR, e);
        }
    }

    /**
     * Processes an array of X.509 certificates from the server's certificate chain.
     * For each certificate, it extracts detailed information using {@link CertificateValidator#getCertificateInfo(X509Certificate)}
     * and logs this information. The details for all certificates are then stored in the {@code result} map.
     *
     * @param certs An array of {@link X509Certificate} representing the server's certificate chain.
     * @throws Exception If an error occurs while extracting information from any of the certificates.
     */
    private void processCertificates(X509Certificate[] certs) throws Exception {
        logger.info("→ Server sent {} certificate(s):", certs.length);
        result.put("certificateCount", certs.length);
        
        @SuppressWarnings("unchecked")
        Map<String, Object>[] certDetails = (Map<String, Object>[]) new Map[certs.length];
        for (int i = 0; i < certs.length; i++) {
            logger.info("Certificate [{}]", (i + 1));
            certDetails[i] = certValidator.getCertificateInfo(certs[i]);
            logger.info(""); // Adds a blank line for readability in logs after each certificate's details
        }
        result.put("certificates", certDetails);
    }
}