package org.example.ssl;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple SSL client for establishing HTTPS connections and retrieving basic SSL/TLS information.
 * This client allows configuration of timeouts, redirect following, and a custom SSLSocketFactory
 * (e.g., for mTLS). It is primarily used to initiate a connection and extract raw certificate data
 * for further processing by other components like {@link org.example.cert.CertificateValidator}.
 */
public class SSLClient {
    private static final Logger logger = LoggerFactory.getLogger(SSLClient.class);
    /** Default timeout for connection and read operations, in milliseconds (10 seconds). */
    private static final int DEFAULT_TIMEOUT = 10000; 

    /** Timeout for establishing the connection, in milliseconds. */
    private final int connectTimeout;
    /** Timeout for reading data from the established connection, in milliseconds. */
    private final int readTimeout;
    /** Flag indicating whether HTTP redirects should be followed. */
    private final boolean followRedirects;
    /** Optional custom SSLSocketFactory, e.g., for client certificate authentication (mTLS). */
    private final SSLSocketFactory sslSocketFactory; // Can be null
    /** Holds the current active HttpsURLConnection. */
    private HttpsURLConnection currentConnection;

    /**
     * Default constructor. Initializes with default timeout values (10 seconds),
     * no redirect following, and no custom SSLSocketFactory.
     */
    public SSLClient() {
        this(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT, false, null);
    }

    /**
     * Constructs an SSLClient with specified connection parameters.
     *
     * @param connectTimeout    The timeout for establishing a connection, in milliseconds.
     * @param readTimeout       The timeout for reading data from the connection, in milliseconds.
     * @param followRedirects   True if the client should automatically follow HTTP redirects; false otherwise.
     * @param sslSocketFactory  An optional {@link SSLSocketFactory} to be used for creating SSL sockets.
     *                          This can be used to configure mTLS by providing a factory initialized
     *                          with a client KeyManager. If null, the default SSLSocketFactory is used.
     */
    public SSLClient(int connectTimeout, int readTimeout, boolean followRedirects, SSLSocketFactory sslSocketFactory) {
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.followRedirects = followRedirects;
        this.sslSocketFactory = sslSocketFactory;
        logger.debug("SSLClient initialized: connectTimeout={}, readTimeout={}, followRedirects={}, customSslSocketFactory={}",
                     connectTimeout, readTimeout, followRedirects, (sslSocketFactory != null));
    }

    /**
     * Establishes an HTTPS connection to the specified URL and retrieves connection details,
     * including the server's certificate chain. This method primarily focuses on the connection
     * and data retrieval; detailed certificate validation (trust, revocation) is typically
     * handled by other components using the data returned in {@link SSLConnectionResult}.
     *
     * @param url The HTTPS URL to connect to. Must not be null and must use the HTTPS protocol.
     * @return An {@link SSLConnectionResult} object containing details of the connection attempt,
     *         including success status, server certificates, cipher suite, HTTP response code,
     *         and hostname verification status. If the connection fails at any stage (e.g., handshake, timeout),
     *         the {@code success} flag in the result will be false, and an exception may be included.
     * @throws IllegalArgumentException if the provided URL is null or not an HTTPS URL.
     */
    public SSLConnectionResult connect(URL url) {
        if (url == null) {
            logger.error("Connection attempt with a null URL.");
            throw new IllegalArgumentException("URL cannot be null");
        }
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            logger.error("Connection attempt to non-HTTPS URL: {}", url);
            throw new IllegalArgumentException("URL must use HTTPS protocol. Provided: " + url.getProtocol());
        }
        
        logger.info("Attempting to connect to {}...", url);
        try {
            currentConnection = (HttpsURLConnection) url.openConnection();
            
            // Configure connection parameters
            currentConnection.setConnectTimeout(connectTimeout);
            currentConnection.setReadTimeout(readTimeout);
            currentConnection.setInstanceFollowRedirects(followRedirects); // Controls if HttpsURLConnection follows 3xx redirects.
            
            // Apply custom SSLSocketFactory if provided (e.g., for mTLS)
            if (sslSocketFactory != null) {
                currentConnection.setSSLSocketFactory(sslSocketFactory);
                logger.debug("Custom SSLSocketFactory set for the connection.");
            }

            // Establish the connection (this also performs the SSL handshake)
            logger.debug("Initiating connection and SSL handshake to {}...", url);
            currentConnection.connect();
            logger.info("Successfully connected to {}. Handshake complete.", url);
            
            // Retrieve connection and certificate information
            int responseCode = currentConnection.getResponseCode();
            String cipherSuite = currentConnection.getCipherSuite();
            logger.debug("Retrieved HTTP response code: {} and cipher suite: {} from {}", responseCode, cipherSuite, url);
            
            java.security.cert.Certificate[] serverCertificates = currentConnection.getServerCertificates();
            if (serverCertificates == null || serverCertificates.length == 0) {
                logger.warn("No server certificates received from {}.", url);
                // This is unusual for a successful HTTPS connection but handle defensively.
                return new SSLConnectionResult(false, new ArrayList<>(), new CertificateException("No server certificates received."), cipherSuite, responseCode, false);
            }
            
            List<X509Certificate> x509CertChain = new ArrayList<>();
            for (java.security.cert.Certificate cert : serverCertificates) {
                if (cert instanceof X509Certificate) {
                    x509CertChain.add((X509Certificate) cert);
                } else {
                    logger.warn("Encountered a non-X509Certificate in the server's certificate chain from {}.", url);
                }
            }
            logger.debug("Retrieved {} X.509 certificates from {}.", x509CertChain.size(), url);

            // Perform basic hostname verification using the connection's verifier
            boolean hostnameVerified = verifyHostname(currentConnection, url.getHost());
            
            return new SSLConnectionResult(
                true,          // success
                x509CertChain, // certificateChain
                null,          // exception
                cipherSuite,
                responseCode,
                hostnameVerified
            );

        } catch (javax.net.ssl.SSLHandshakeException e) {
            logger.error("SSL handshake failed for {}: {}", url, e.getMessage(), e);
            return new SSLConnectionResult(false, null, e, null, 0, false);
        } catch (java.net.SocketTimeoutException e) {
            logger.error("Connection or read timeout for {}: {}", url, e.getMessage(), e);
            return new SSLConnectionResult(false, null, e, null, 0, false);
        } catch (Exception e) { // Catch other IOExceptions or general errors
            logger.error("Connection failed for {}: {}", url, e.getMessage(), e);
            return new SSLConnectionResult(false, null, e, null, 0, false);
        }
    }

    /**
     * Verifies the server's hostname against the established SSL session.
     * This method uses the {@link HttpsURLConnection}'s configured {@link javax.net.ssl.HostnameVerifier}.
     *
     * @param conn     The active {@link HttpsURLConnection}.
     * @param hostname The hostname to verify against the certificate.
     * @return True if the hostname is verified, false otherwise.
     */
    private boolean verifyHostname(HttpsURLConnection conn, String hostname) {
        logger.debug("Performing hostname verification for host '{}'.", hostname);
        try {
            // getSSLSession() should be called after connect() and after certificates are available.
            var sessionOptional = conn.getSSLSession(); // Returns Optional<SSLSession>
            if (sessionOptional.isEmpty()) {
                logger.error("No SSL session available for hostname verification against host '{}'. This might indicate a connection issue.", hostname);
                return false;
            }
            // Use the connection's hostname verifier.
            boolean verified = conn.getHostnameVerifier().verify(hostname, sessionOptional.get());
            logger.info("Hostname verification for '{}': {}", hostname, verified ? "Passed" : "Failed");
            return verified;
        } catch (Exception e) {
            logger.error("Exception during hostname verification for host '{}': {}", hostname, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Closes the current HTTPS connection if it is active.
     * It's good practice to call this after the connection is no longer needed.
     */
    public void close() {
        if (currentConnection != null) {
            logger.debug("Disconnecting HttpsURLConnection for {}.", currentConnection.getURL());
            currentConnection.disconnect();
            currentConnection = null;
        } else {
            logger.debug("Close called, but no active connection to disconnect.");
        }
    }
}
