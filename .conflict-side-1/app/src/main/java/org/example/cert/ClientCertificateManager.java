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

public class ClientCertificateManager {
    private static final Logger logger = LoggerFactory.getLogger(ClientCertificateManager.class);
    private final SSLTestConfig config;

    public ClientCertificateManager(SSLTestConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        this.config = config;
    }

    public SSLContext createSSLContext() throws Exception {
        if (config.getClientCertFile() == null || config.getClientKeyFile() == null) {
            logger.debug("No client certificate configuration provided");
            return null;
        }

        if (!config.getClientCertFile().exists()) {
            throw new FileNotFoundException("Client certificate file not found: " + config.getClientCertFile());
        }
        if (!config.getClientKeyFile().exists()) {
            throw new FileNotFoundException("Client key file not found: " + config.getClientKeyFile());
        }

        try {
            // Load client certificate and private key
            KeyStore keyStore = loadClientCertificate();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] password = config.getClientKeyPassword() != null ? 
                    config.getClientKeyPassword().toCharArray() : null;
            kmf.init(keyStore, password);

            // Create SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            logger.debug("SSL context initialized with client certificate");
            return sslContext;
        } catch (Exception e) {
            logger.error("Failed to initialize client certificate: {}", e.getMessage());
            throw new Exception("Failed to initialize client certificate: " + e.getMessage(), e);
        }
    }

    private KeyStore loadClientCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        try {
            // Load certificate chain
            List<X509Certificate> certChain = loadCertificateChain(config.getClientCertFile());
            if (certChain.isEmpty()) {
                throw new CertificateException("No certificates found in certificate file");
            }
            
            X509Certificate cert = certChain.get(0);
            logger.debug("Loaded client certificate: {}", cert.getSubjectX500Principal());
            
            // Load private key
            PrivateKey privateKey = loadPrivateKey(config.getClientKeyFile());
            logger.debug("Loaded private key: {}", privateKey.getAlgorithm());

            // Add to keystore
            char[] password = config.getClientKeyPassword() != null ? 
                    config.getClientKeyPassword().toCharArray() : null;
            keyStore.setKeyEntry("client", privateKey, password, 
                    certChain.toArray(new X509Certificate[0]));

            return keyStore;
        } catch (Exception e) {
            logger.error("Failed to load client certificate: {}", e.getMessage());
            throw new Exception("Failed to load client certificate: " + e.getMessage(), e);
        }
    }

    private List<X509Certificate> loadCertificateChain(File certFile) throws Exception {
        if (!certFile.exists() || !certFile.canRead()) {
            throw new IOException("Cannot read certificate file: " + certFile);
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(certFile))) {
            if (config.getClientCertFormat() == SSLTestConfig.CertificateFormat.PEM) {
                return loadPEMCertificateChain(reader);
            } else {
                return loadDERCertificate(certFile);
            }
        }
    }

    private List<X509Certificate> loadPEMCertificateChain(BufferedReader reader) throws Exception {
        List<X509Certificate> certChain = new ArrayList<>();
        StringBuilder pemContent = new StringBuilder();
        String line;
        boolean inCertificate = false;
        
        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN CERTIFICATE")) {
                if (inCertificate) {
                    // Process previous certificate
                    if (pemContent.length() > 0) {
                        certChain.add(parsePEMCertificate(pemContent.toString()));
                        pemContent = new StringBuilder();
                    }
                }
                inCertificate = true;
                continue;
            }
            if (line.contains("END CERTIFICATE")) {
                inCertificate = false;
                if (pemContent.length() > 0) {
                    certChain.add(parsePEMCertificate(pemContent.toString()));
                    pemContent = new StringBuilder();
                }
                continue;
            }
            if (inCertificate) {
                pemContent.append(line);
            }
        }
        
        // Process last certificate if exists
        if (inCertificate && pemContent.length() > 0) {
            certChain.add(parsePEMCertificate(pemContent.toString()));
        }
        
        if (certChain.isEmpty()) {
            throw new CertificateException("No certificates found in PEM file");
        }
        
        return certChain;
    }

    private List<X509Certificate> loadDERCertificate(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = new FileInputStream(certFile)) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            List<X509Certificate> certChain = new ArrayList<>();
            certChain.add(cert);
            return certChain;
        }
    }

    private X509Certificate parsePEMCertificate(String pemContent) throws CertificateException {
        try {
            byte[] certBytes = Base64.getDecoder().decode(pemContent);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (IllegalArgumentException e) {
            throw new CertificateException("Invalid base64 encoding in certificate", e);
        }
    }

    private PrivateKey loadPrivateKey(File keyFile) throws Exception {
        if (!keyFile.exists() || !keyFile.canRead()) {
            throw new IOException("Cannot read key file: " + keyFile);
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(keyFile))) {
            if (config.getClientCertFormat() == SSLTestConfig.CertificateFormat.PEM) {
                return loadPEMPrivateKey(reader);
            } else {
                return loadDERPrivateKey(keyFile);
            }
        }
    }

    private PrivateKey loadPEMPrivateKey(BufferedReader reader) throws Exception {
        StringBuilder pemContent = new StringBuilder();
        String line;
        boolean inPrivateKey = false;
        boolean isEncrypted = false;
        
        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
                inPrivateKey = true;
                isEncrypted = true;
                continue;
            }
            if (line.contains("BEGIN PRIVATE KEY") || line.contains("BEGIN RSA PRIVATE KEY")) {
                inPrivateKey = true;
                continue;
            }
            if (line.contains("END PRIVATE KEY") || line.contains("END RSA PRIVATE KEY") || 
                line.contains("END ENCRYPTED PRIVATE KEY")) {
                inPrivateKey = false;
                break;
            }
            if (inPrivateKey) {
                pemContent.append(line);
            }
        }
        
        if (pemContent.length() == 0) {
            throw new IOException("No private key found in PEM file");
        }
        
        byte[] keyBytes = Base64.getDecoder().decode(pemContent.toString());
        
        if (isEncrypted) {
            if (config.getClientKeyPassword() == null) {
                throw new IOException("Encrypted private key requires a password");
            }
            return loadEncryptedPrivateKey(keyBytes, config.getClientKeyPassword());
        }
        
        return loadUnencryptedPrivateKey(keyBytes);
    }

    private PrivateKey loadDERPrivateKey(File keyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        return loadUnencryptedPrivateKey(keyBytes);
    }

    private PrivateKey loadEncryptedPrivateKey(byte[] encryptedKeyBytes, String password) throws Exception {
        try {
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encryptedKeyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            PKCS8EncodedKeySpec keySpec2 = encryptedPrivateKeyInfo.getKeySpec(secretKey);
            
            return loadUnencryptedPrivateKey(keySpec2.getEncoded());
        } catch (Exception e) {
            logger.error("Failed to decrypt private key: {}", e.getMessage());
            throw new IOException("Failed to decrypt private key: " + e.getMessage(), e);
        }
    }

    private PrivateKey loadUnencryptedPrivateKey(byte[] keyBytes) throws Exception {
        // Try different key formats
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (Exception e2) {
                try {
                    KeyFactory kf = KeyFactory.getInstance("Ed25519");
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                } catch (Exception e3) {
                    logger.error("Failed to load private key: {}", e3.getMessage());
                    throw new IOException("Failed to load private key: " + e3.getMessage(), e3);
                }
            }
        }
    }
} 