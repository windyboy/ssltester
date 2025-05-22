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
 * SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证
 */
@Command(name = "ssltest", 
        description = "SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证",
        mixinStandardHelpOptions = true)
public class SSLTest implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(SSLTest.class);

    // Exit codes
    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_INVALID_ARGS = 1;
    private static final int EXIT_SSL_HANDSHAKE_ERROR = 2;
    private static final int EXIT_CONNECTION_ERROR = 3;
    private static final int EXIT_CERTIFICATE_VALIDATION_ERROR = 4; // As per README
    private static final int EXIT_HOSTNAME_VERIFICATION_ERROR = 5;
    private static final int EXIT_UNEXPECTED_ERROR = 99;

    @CommandLine.Mixin
    private final SSLTestConfig config;
    private final CertificateValidator certValidator;
    private final ResultFormatter resultFormatter;
    private final ClientCertificateManager clientCertManager;
    private final Map<String, Object> result = new HashMap<>();

    // No-arg constructor for CLI use
    public SSLTest() {
        this(new SSLTestConfig());
    }

    // Constructor for test/dependency injection
    public SSLTest(SSLTestConfig config) {
        this.config = config;
        this.certValidator = new CertificateValidator(config.getKeystoreFile(), config.getKeystorePassword(), config);
        this.resultFormatter = new ResultFormatter(config);
        this.clientCertManager = new ClientCertificateManager(config);
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new SSLTest()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        logger.info("Starting SSL test for URL: {}", config.getUrl()); // Added before config URL can be null
        try {
            // Initial URL check
            String urlString = config.getUrl();
            if (urlString == null || urlString.trim().isEmpty()) {
                logger.error("URL is required but was not provided or was empty.");
                throw new SSLTestException("URL is required.", EXIT_INVALID_ARGS);
            }
            logger.info("Target URL specified: {}", urlString);


            // Load configuration from file if specified
            if (config.getConfigFile() != null) {
                logger.info("Loading configuration from file: {}", config.getConfigFile().getAbsolutePath());
                try {
                    Map<String, Object> fileConfig = SSLTestConfigFile.loadConfig(config.getConfigFile());
                    SSLTestConfigFile.applyConfig(fileConfig, config); // This updates the 'config' object
                    logger.info("Successfully loaded and applied configuration from {}.", config.getConfigFile().getAbsolutePath());
                    // Log some key configurations if needed, e.g., timeout, OCSP/CRL status
                    logger.debug("Effective configuration: ConnectionTimeout={}, ReadTimeout={}, OCSP={}, CRL={}", 
                                 config.getConnectionTimeout(), config.getReadTimeout(), config.isCheckOCSP(), config.isCheckCRL());
                } catch (IOException e) {
                    logger.error("Failed to load configuration file '{}': {}", config.getConfigFile().getAbsolutePath(), e.getMessage(), e);
                    throw new SSLTestException("Failed to load configuration file: " + e.getMessage(), EXIT_INVALID_ARGS, e);
                }
            }
            
            // Validate and parse the URL (which might have been updated from config file)
            URL parsedUrl = parseAndValidateUrl(config.getUrl()); // Use potentially updated URL
            
            // Main SSL connection and validation logic
            testSSLConnection(parsedUrl);
            
            // Output successful results
            logger.info("SSL test completed successfully for URL: {}.", parsedUrl);
            resultFormatter.formatAndOutput(result); // result map is populated by testSSLConnection & processCertificates
            return EXIT_SUCCESS;
        } catch (SSLTestException e) {
            // Handle known SSLTest specific errors (includes validation, handshake, connection issues)
            logger.error("SSLTestException caught: Message='{}', ExitCode={}", e.getMessage(), e.getExitCode(), e.getCause());
            handleError(e.getMessage(), e.getCause(), e.getExitCode());
            return e.getExitCode();
        } catch (Exception e) {
            // Handle any other unexpected errors
            logger.error("Unexpected error during SSL test execution: {}", e.getMessage(), e);
            handleError("Unexpected error: " + e.getMessage(), e, EXIT_UNEXPECTED_ERROR);
            return EXIT_UNEXPECTED_ERROR;
        }
    }

    private void handleError(String message, Throwable cause, int exitCode) {
        // This method is responsible for formatting the error output and populating the result map for errors.
        // ResultFormatter.logError is already called by SSLTestConfig's ResultFormatter instance.
        // This method ensures the error information is also part of the structured output (JSON/YAML/Text).
        logger.error("Error handled: '{}', Exit Code: {}. Preparing error output.", message, exitCode);
        if (cause != null) {
            logger.debug("Underlying cause of error: ", cause);
        }
        
        result.put("error", message);
        result.put("status", "failed"); // Indicate failure in the result map
        if (cause != null) {
            // Include only a summary of the cause to avoid deeply nested objects in JSON/YAML if cause is complex.
            result.put("errorCause", cause.getClass().getName() + (cause.getMessage() != null ? ": " + cause.getMessage() : ""));
        }
        result.put("exitCode", exitCode);
        
        // Ensure resultFormatter is available; it should be unless SSLTest constructor failed.
        if (resultFormatter != null) {
            resultFormatter.formatAndOutput(result);
        } else {
            // Fallback if resultFormatter is somehow null (should not happen in normal flow)
            System.err.println("FATAL: ResultFormatter not initialized. Error: " + message);
            if (cause != null) {
                System.err.println("Cause: " + cause.getMessage());
            }
        }
    }

    private URL parseAndValidateUrl(String urlStr) throws SSLTestException {
        logger.debug("Attempting to parse and validate URL: {}", urlStr);
        if (urlStr == null || urlStr.trim().isEmpty()) { // Check again in case config reloaded a blank URL
            logger.error("URL is null or empty after config processing.");
            throw new SSLTestException("URL became null or empty after config processing.", EXIT_INVALID_ARGS);
        }
        try {
            URI uri = new URI(urlStr);
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                logger.error("Invalid URL scheme: {}. URL must use HTTPS.", uri.getScheme());
                throw new SSLTestException("URL must use HTTPS protocol. Found: " + uri.getScheme(), EXIT_INVALID_ARGS);
            }
            logger.debug("URL successfully parsed and validated: {}", uri.toURL());
            return uri.toURL();
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
     * Sets up the HTTPS connection, performs the handshake, validates certificates and hostname.
     * Populates the `result` map with connection and certificate details.
     * Throws SSLTestException for specific failure types, mapped to exit codes.
     */
    private void testSSLConnection(URL url) throws SSLTestException {
        HttpsURLConnection conn = null;
        logger.info("Attempting to establish SSL connection to: {}", url.toString());
        try {
            // Setup connection details (timeouts, redirects, client certs)
            conn = setupConnection(url);
            
            // This initiates the SSL handshake
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

            // Validate the certificate chain (including trust and revocation)
            List<CertificateDetails> certificateDetailsList = certValidator.validateCertificateChain(serverCerts);
            
            // Validate hostname against the end-entity certificate
            if (serverCerts[0] instanceof X509Certificate) {
                validateHostname(url, (X509Certificate) serverCerts[0]);
            } else {
                logger.error("End-entity certificate is not an X509Certificate instance for {}.", url.toString());
                throw new SSLTestException("End-entity certificate is not X509.", EXIT_CERTIFICATE_VALIDATION_ERROR);
            }
            
            // Process and store certificate details for output
            processCertificates(certificateDetailsList);

            logger.info("✅ SSL connection, certificate validation, and hostname verification succeeded for {}.", url.toString());
            result.put("status", "success"); // Overall success status

        } catch (javax.net.ssl.SSLHandshakeException e) {
            logger.error("SSL handshake failed for {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("SSL handshake failed: " + e.getMessage(), EXIT_SSL_HANDSHAKE_ERROR, e);
        } catch (java.security.cert.CertificateException e) {
            // This catches exceptions from certValidator.validateCertificateChain (e.g., trust, revocation)
            logger.error("Certificate validation failed for {}: {}", url.toString(), e.getMessage(), e);
            // The message from CertificateException (e.g., "Certificate ... REVOKED...") is preserved.
            throw new SSLTestException("Certificate validation failed: " + e.getMessage(), EXIT_CERTIFICATE_VALIDATION_ERROR, e);
        } catch (SSLTestException e) { // Re-throw SSLTestExceptions (e.g., from validateHostname)
            throw e;
        } catch (IOException e) { // Catch other IOExceptions (e.g., network issues not part of handshake)
            logger.error("IO error during connection to {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("IO error during connection: " + e.getMessage(), EXIT_CONNECTION_ERROR, e);
        } catch (Exception e) { // Catch-all for any other unexpected errors
            logger.error("Unexpected error during SSL connection or validation for {}: {}", url.toString(), e.getMessage(), e);
            throw new SSLTestException("Unexpected error during SSL connection or validation: " + e.getMessage(), EXIT_UNEXPECTED_ERROR, e);
        } finally {
            if (conn != null) {
                logger.debug("Disconnecting HttpsURLConnection for {}.", url.toString());
                conn.disconnect();
            }
        }
    }

    private HttpsURLConnection setupConnection(URL url) throws java.io.IOException {
        logger.info("Connecting to {} …", url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(config.getConnectionTimeout());
        conn.setReadTimeout(config.getReadTimeout());
        conn.setInstanceFollowRedirects(config.isFollowRedirects());

        // Set up client certificate if configured
        try {
            SSLContext sslContext = clientCertManager.createSSLContext();
            if (sslContext != null) {
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                logger.info("Using client certificate for authentication");
            }
        } catch (Exception e) {
            logger.warn("Failed to set up client certificate: {}", e.getMessage());
        }

        conn.connect();
        return conn;
    }

    private void validateHostname( URL url, X509Certificate cert) throws SSLTestException {
        try {
            String hostname = url.getHost();
            if (!certValidator.verifyHostname(cert, hostname)) {
                throw new SSLTestException("Hostname verification failed for host " + hostname,
                        EXIT_HOSTNAME_VERIFICATION_ERROR);
            }
            logger.info("→ Hostname verification passed");
            result.put("hostnameVerified", true);
        } catch (Exception e) {
            throw new SSLTestException("主机名验证错误: " + e.getMessage(), EXIT_HOSTNAME_VERIFICATION_ERROR, e);
        }
    }

    private void processCertificates(List<CertificateDetails> certDetailsList) {
        List<Map<String, Object>> outputCertList = new ArrayList<>();
        for (CertificateDetails details : certDetailsList) {
            Map<String, Object> certMap = new HashMap<>();
            certMap.put("subjectDN", details.getSubjectDN());
            certMap.put("issuerDN", details.getIssuerDN());
            certMap.put("version", details.getVersion());
            certMap.put("serialNumber", details.getSerialNumber());
            certMap.put("validFrom", details.getValidFrom());
            certMap.put("validUntil", details.getValidUntil());
            certMap.put("signatureAlgorithm", details.getSignatureAlgorithm());
            certMap.put("publicKeyAlgorithm", details.getPublicKeyAlgorithm());
            certMap.put("subjectAlternativeNames", details.getSubjectAlternativeNames());
            certMap.put("selfSigned", details.isSelfSigned());
            certMap.put("expired", details.isExpired());
            certMap.put("notYetValid", details.isNotYetValid());
            certMap.put("trustStatus", details.getTrustStatus().name());
            certMap.put("revocationStatus", details.getRevocationStatus().name());
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
        logger.info("→ Server sent {} certificate(s):", certDetailsList.size());
    }
}
