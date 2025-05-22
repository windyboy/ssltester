package org.example.cert;

import org.example.config.SSLTestConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Manages client certificates for mutual TLS (mTLS) authentication.
 * This class is responsible for loading client certificates and private keys from files,
 * and creating an {@link SSLContext} configured for mTLS.
 */
public class ClientCertificateManager {
    private static final Logger logger = LoggerFactory.getLogger(ClientCertificateManager.class);
    /** Configuration containing paths and passwords for client certificates and keys. */
    private final SSLTestConfig config;

    /**
     * Constructs a ClientCertificateManager with the given SSL test configuration.
     *
     * @param config The {@link SSLTestConfig} containing client certificate settings. Must not be null.
     * @throws IllegalArgumentException if the provided config is null.
     */
    public ClientCertificateManager(SSLTestConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null for ClientCertificateManager.");
        }
        this.config = config;
        logger.debug("ClientCertificateManager initialized.");
    }

    /**
     * Creates an {@link SSLContext} configured with the client certificate and private key
     * specified in the {@link SSLTestConfig}.
     * If client certificate or key files are not specified in the config, this method returns null.
     *
     * @return An {@link SSLContext} initialized for mTLS, or null if client certificate/key is not configured.
     * @throws Exception If there's an error loading the certificate/key or initializing the SSLContext
     *                   (e.g., file not found, incorrect password, unsupported format).
     */
    public SSLContext createSSLContext() throws Exception {
        if (config.getClientCertFile() == null || config.getClientKeyFile() == null) {
            logger.info("Client certificate or key file not specified in configuration. mTLS will not be configured.");
            return null;
        }

        logger.info("Attempting to create SSLContext with client certificate: {} and key: {}", 
                    config.getClientCertFile().getAbsolutePath(), config.getClientKeyFile().getAbsolutePath());

        if (!config.getClientCertFile().exists()) {
            throw new FileNotFoundException("Client certificate file not found: " + config.getClientCertFile().getAbsolutePath());
        }
        if (!config.getClientKeyFile().exists()) {
            throw new FileNotFoundException("Client key file not found: " + config.getClientKeyFile().getAbsolutePath());
        }

        try {
            // Load client certificate and private key into a KeyStore
            KeyStore keyStore = loadClientCertificate();
            
            // Initialize KeyManagerFactory with the KeyStore
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] keyPassword = config.getClientKeyPassword() != null ? 
                                 config.getClientKeyPassword().toCharArray() : new char[0]; // Use empty array if null
            kmf.init(keyStore, keyPassword);
            logger.debug("KeyManagerFactory initialized successfully.");

            // Create and initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS"); // Or specify a more specific version like TLSv1.2, TLSv1.3
            sslContext.init(kmf.getKeyManagers(), null, null); // Uses default TrustManager
            logger.info("SSLContext successfully initialized with client certificate for mTLS.");
            return sslContext;
        } catch (Exception e) {
            logger.error("Failed to create SSLContext for mTLS: {}", e.getMessage(), e);
            // Re-throw as a generic Exception to be handled by the caller, or a more specific custom exception.
            throw new Exception("Failed to initialize SSLContext for client authentication: " + e.getMessage(), e);
        }
    }

    /**
     * Loads the client certificate chain and private key into a PKCS12 KeyStore.
     * The certificate and key are read from files specified in the configuration.
     *
     * @return A {@link KeyStore} instance containing the client's key entry.
     * @throws Exception if loading or parsing fails.
     */
    private KeyStore loadClientCertificate() throws Exception {
        logger.debug("Loading client certificate and key into a new PKCS12 KeyStore.");
        KeyStore keyStore = KeyStore.getInstance("PKCS12"); // PKCS12 is a common format for storing private keys and certs
        keyStore.load(null, null); // Initialize an empty keystore

        try {
            // Load certificate chain from the configured file
            List<X509Certificate> certChain = loadCertificateChain(config.getClientCertFile());
            if (certChain.isEmpty()) {
                throw new CertificateException("No certificates found in client certificate file: " + config.getClientCertFile().getAbsolutePath());
            }
            logger.info("Successfully loaded {} certificate(s) from client certificate file: {}", certChain.size(), config.getClientCertFile().getAbsolutePath());
            
            // Load private key from the configured file
            PrivateKey privateKey = loadPrivateKey(config.getClientKeyFile());
            logger.info("Successfully loaded private key ({}) from file: {}", privateKey.getAlgorithm(), config.getClientKeyFile().getAbsolutePath());

            // Set the key entry in the KeyStore
            char[] keyPassword = config.getClientKeyPassword() != null ? 
                                 config.getClientKeyPassword().toCharArray() : new char[0];
            // The alias "client" is arbitrary but conventional.
            keyStore.setKeyEntry("client", privateKey, keyPassword, certChain.toArray(new X509Certificate[0]));
            logger.debug("Client key and certificate chain set in KeyStore under alias 'client'.");

            return keyStore;
        } catch (Exception e) {
            // Log specific error and re-throw to ensure createSSLContext handles it.
            logger.error("Error loading client certificate/key into KeyStore: {}", e.getMessage(), e);
            throw e; 
        }
    }

    /**
     * Loads a chain of X.509 certificates from the specified file.
     * Supports PEM or DER format based on configuration.
     *
     * @param certFile The file containing the certificate(s).
     * @return A list of {@link X509Certificate} objects.
     * @throws Exception if reading or parsing fails.
     */
    private List<X509Certificate> loadCertificateChain(File certFile) throws Exception {
        if (certFile == null || !certFile.exists() || !certFile.canRead()) {
            throw new IOException("Client certificate file is null, does not exist, or cannot be read: " + (certFile != null ? certFile.getAbsolutePath() : "null"));
        }
        logger.debug("Loading certificate chain from file: {}, format: {}", certFile.getAbsolutePath(), config.getClientCertFormat());

        try (BufferedReader reader = new BufferedReader(new FileReader(certFile))) { // Used for PEM
            if (config.getClientCertFormat() == SSLTestConfig.CertificateFormat.PEM) {
                return loadPEMCertificateChain(reader);
            } else { // DER format
                return loadDERCertificate(certFile);
            }
        }
    }

    /**
     * Loads a certificate chain from a PEM formatted reader.
     * Handles multiple concatenated certificates in a single PEM file.
     *
     * @param reader The reader for the PEM content.
     * @return A list of parsed {@link X509Certificate}s.
     * @throws Exception if parsing fails or no certificates are found.
     */
    private List<X509Certificate> loadPEMCertificateChain(BufferedReader reader) throws Exception {
        logger.debug("Loading PEM certificate chain.");
        List<X509Certificate> certChain = new ArrayList<>();
        StringBuilder pemContent = new StringBuilder();
        String line;
        boolean inCertificate = false;
        
        while ((line = reader.readLine()) != null) {
            if (line.contains("-----BEGIN CERTIFICATE-----")) { // Standard PEM header
                if (inCertificate && pemContent.length() > 0) { // Should not happen if format is correct
                     logger.warn("Found 'BEGIN CERTIFICATE' while already processing a certificate. Previous content will be parsed.");
                    certChain.add(parsePEMCertificate(pemContent.toString()));
                }
                pemContent = new StringBuilder(); // Reset for new certificate
                inCertificate = true;
                continue; // Skip the BEGIN line itself
            }
            if (line.contains("-----END CERTIFICATE-----")) { // Standard PEM footer
                if (inCertificate && pemContent.length() > 0) {
                    certChain.add(parsePEMCertificate(pemContent.toString()));
                    pemContent = new StringBuilder(); // Reset
                }
                inCertificate = false;
                continue; // Skip the END line itself
            }
            if (inCertificate) {
                pemContent.append(line.trim()); // Trim whitespace which might affect Base64 decoding
            }
        }
        
        // In case the file ends mid-certificate or without a final newline (less common but possible)
        if (inCertificate && pemContent.length() > 0) {
            logger.warn("PEM file ended while still in certificate content. Attempting to parse buffered content.");
            certChain.add(parsePEMCertificate(pemContent.toString()));
        }
        
        if (certChain.isEmpty()) {
            throw new CertificateException("No certificates found in PEM input.");
        }
        logger.debug("Parsed {} certificate(s) from PEM input.", certChain.size());
        return certChain;
    }

    /**
     * Loads a single X.509 certificate from a DER encoded file.
     *
     * @param certFile The DER encoded certificate file.
     * @return A list containing the single parsed {@link X509Certificate}.
     * @throws Exception if parsing fails.
     */
    private List<X509Certificate> loadDERCertificate(File certFile) throws Exception {
        logger.debug("Loading DER certificate from file: {}", certFile.getAbsolutePath());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = new FileInputStream(certFile)) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            List<X509Certificate> certChain = new ArrayList<>();
            certChain.add(cert);
            logger.debug("Successfully loaded 1 DER certificate: {}", cert.getSubjectX500Principal());
            return certChain;
        }
    }

    /**
     * Parses a single PEM-encoded certificate string (Base64 content only, without headers/footers).
     *
     * @param pemContent The Base64 encoded certificate content.
     * @return The parsed {@link X509Certificate}.
     * @throws CertificateException if parsing fails or encoding is invalid.
     */
    private X509Certificate parsePEMCertificate(String pemContent) throws CertificateException {
        logger.trace("Parsing PEM certificate content (length: {}).", pemContent.length());
        try {
            byte[] certBytes = Base64.getDecoder().decode(pemContent.replaceAll("\\s", "")); // Remove all whitespace
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (IllegalArgumentException e) {
            logger.error("Invalid Base64 encoding in PEM certificate content.", e);
            throw new CertificateException("Invalid Base64 encoding in certificate", e);
        } catch (CertificateException e) {
            logger.error("Failed to parse certificate from PEM content.", e);
            throw e;
        }
    }

    /**
     * Loads a private key from the specified file.
     * Supports PEM or DER format based on configuration.
     *
     * @param keyFile The file containing the private key.
     * @return The loaded {@link PrivateKey}.
     * @throws Exception if reading or parsing fails.
     */
    private PrivateKey loadPrivateKey(File keyFile) throws Exception {
        if (keyFile == null || !keyFile.exists() || !keyFile.canRead()) {
             throw new IOException("Client key file is null, does not exist, or cannot be read: " + (keyFile != null ? keyFile.getAbsolutePath() : "null"));
        }
        logger.debug("Loading private key from file: {}, format: {}", keyFile.getAbsolutePath(), config.getClientCertFormat());

        try (BufferedReader reader = new BufferedReader(new FileReader(keyFile))) { // Used for PEM
            if (config.getClientCertFormat() == SSLTestConfig.CertificateFormat.PEM) {
                return loadPEMPrivateKey(reader);
            } else { // DER format
                return loadDERPrivateKey(keyFile);
            }
        }
    }

    /**
     * Loads a private key from a PEM formatted reader.
     * Handles both encrypted (PKCS#8) and unencrypted (PKCS#1, PKCS#8) PEM formats.
     *
     * @param reader The reader for the PEM content.
     * @return The loaded {@link PrivateKey}.
     * @throws Exception if parsing fails, password is required but not provided, or decryption fails.
     */
    private PrivateKey loadPEMPrivateKey(BufferedReader reader) throws Exception {
        logger.debug("Loading PEM private key.");
        StringBuilder pemContent = new StringBuilder();
        String line;
        boolean inPrivateKey = false;
        boolean isEncrypted = false;
        
        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
                inPrivateKey = true;
                isEncrypted = true;
                pemContent = new StringBuilder(); // Reset for content
                continue;
            }
            // Standard PKCS#8 or PKCS#1 RSA private key
            if (line.contains("BEGIN PRIVATE KEY") || line.contains("BEGIN RSA PRIVATE KEY")) {
                inPrivateKey = true;
                pemContent = new StringBuilder(); // Reset for content
                continue;
            }
            if (line.contains("END ENCRYPTED PRIVATE KEY") || line.contains("END PRIVATE KEY") || line.contains("END RSA PRIVATE KEY")) {
                inPrivateKey = false; // Content for this block is finished
                break; 
            }
            if (inPrivateKey) {
                pemContent.append(line.trim()); // Trim whitespace
            }
        }
        
        if (pemContent.length() == 0) {
            throw new IOException("No private key content found between PEM headers in file.");
        }
        
        byte[] keyBytes = Base64.getDecoder().decode(pemContent.toString().replaceAll("\\s", ""));
        
        if (isEncrypted) {
            logger.debug("Detected encrypted private key.");
            if (config.getClientKeyPassword() == null || config.getClientKeyPassword().isEmpty()) {
                logger.error("Encrypted private key requires a password, but none was provided.");
                throw new IOException("Encrypted private key requires a password.");
            }
            return loadEncryptedPrivateKey(keyBytes, config.getClientKeyPassword());
        }
        
        logger.debug("Detected unencrypted private key.");
        return loadUnencryptedPrivateKey(keyBytes);
    }

    /**
     * Loads a private key from a DER encoded file. Assumed to be unencrypted PKCS#8.
     *
     * @param keyFile The DER encoded key file.
     * @return The loaded {@link PrivateKey}.
     * @throws Exception if reading or parsing fails.
     */
    private PrivateKey loadDERPrivateKey(File keyFile) throws Exception {
        logger.debug("Loading DER private key from file: {}", keyFile.getAbsolutePath());
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        return loadUnencryptedPrivateKey(keyBytes);
    }

    /**
     * Decrypts and loads an encrypted private key (PKCS#8 format).
     *
     * @param encryptedKeyBytes The raw bytes of the encrypted private key.
     * @param password The password for decryption.
     * @return The decrypted {@link PrivateKey}.
     * @throws Exception if decryption or loading fails.
     */
    private PrivateKey loadEncryptedPrivateKey(byte[] encryptedKeyBytes, String password) throws Exception {
        logger.debug("Attempting to decrypt private key.");
        try {
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encryptedKeyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
            PKCS8EncodedKeySpec pkcs8KeySpec = encryptedPrivateKeyInfo.getKeySpec(secretKey);
            logger.debug("Private key decrypted successfully.");
            return loadUnencryptedPrivateKey(pkcs8KeySpec.getEncoded()); // Load the decrypted PKCS#8 bytes
        } catch (Exception e) {
            logger.error("Failed to decrypt private key: {}. Check password or key format.", e.getMessage(), e);
            throw new IOException("Failed to decrypt private key: " + e.getMessage(), e);
        }
    }

    /**
     * Loads an unencrypted private key from its raw PKCS#8 encoded bytes.
     * It tries to parse the key as RSA, EC, or Ed25519.
     *
     * @param keyBytes The raw PKCS#8 encoded bytes of the private key.
     * @return The loaded {@link PrivateKey}.
     * @throws Exception if parsing fails for all attempted key types.
     */
    private PrivateKey loadUnencryptedPrivateKey(byte[] keyBytes) throws Exception {
        logger.debug("Attempting to load unencrypted private key (PKCS#8).");
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        // Try common key algorithms
        String[] keyAlgorithms = {"RSA", "EC", "Ed25519", "DSA"}; // DSA is less common now but included for completeness
        
        for (String algorithm : keyAlgorithms) {
            try {
                KeyFactory kf = KeyFactory.getInstance(algorithm);
                PrivateKey privateKey = kf.generatePrivate(pkcs8KeySpec);
                logger.debug("Successfully loaded unencrypted private key with algorithm: {}", algorithm);
                return privateKey;
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                logger.trace("Failed to load private key as {}: {}", algorithm, e.getMessage());
                // Try next algorithm
            }
        }
        logger.error("Failed to load unencrypted private key. None of the attempted algorithms (RSA, EC, Ed25519, DSA) succeeded.");
        throw new IOException("Unsupported private key format or algorithm.");
    }
} 