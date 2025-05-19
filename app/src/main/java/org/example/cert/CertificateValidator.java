package org.example.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final String INDENT = "   ";

    private final File keystoreFile;
    private final String keystorePassword;

    public CertificateValidator(File keystoreFile, String keystorePassword) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
    }

    public X509Certificate[] validateCertificateChain(Certificate[] certs) throws CertificateException {
        X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);

        String sigAlg = x509Certs[0].getSigAlgName();
        String auth = determineAuthType(sigAlg);

        tm.checkServerTrusted(x509Certs, auth);
        logger.info("→ Certificate chain trusted");
        return x509Certs;
    }

    private TrustManagerFactory initializeTrustManagerFactory() throws CertificateException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if (keystoreFile != null) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(keystoreFile.toURI().toURL().openStream(), 
                        keystorePassword != null ? keystorePassword.toCharArray() : null);
                tmf.init(ks);
            } else {
                tmf.init((KeyStore) null);
            }
            return tmf;
        } catch (Exception e) {
            throw new CertificateException("Failed to initialize trust manager: " + e.getMessage(), e);
        }
    }

    private X509TrustManager findX509TrustManager(TrustManagerFactory tmf) throws CertificateException {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new CertificateException("No X509TrustManager found");
    }

    private String determineAuthType(String sigAlg) {
        String auth = sigAlg.substring(sigAlg.toUpperCase().indexOf("WITH") + 4);
        return "ECDSA".equalsIgnoreCase(auth) ? "ECDHE_ECDSA" : auth;
    }

    public Map<String, Object> getCertificateInfo(X509Certificate cert) throws Exception {
        Map<String, Object> certInfo = new HashMap<>();
        
        String subjectDN = cert.getSubjectX500Principal().getName();
        String issuerDN = cert.getIssuerX500Principal().getName();
        int version = cert.getVersion();
        String serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
        String validFrom = DATE_FORMATTER.format(cert.getNotBefore().toInstant());
        String validUntil = DATE_FORMATTER.format(cert.getNotAfter().toInstant());
        String sigAlg = cert.getSigAlgName();
        String pubKeyAlg = cert.getPublicKey().getAlgorithm();

        logger.info("{} Subject DN    : {}", INDENT, subjectDN);
        logger.info("{} Issuer DN     : {}", INDENT, issuerDN);
        logger.info("{} Version       : {}", INDENT, version);
        logger.info("{} Serial Number : {}", INDENT, serialNumber);
        logger.info("{} Valid From    : {}", INDENT, validFrom);
        logger.info("{} Valid Until   : {}", INDENT, validUntil);
        logger.info("{} Sig. Algorithm: {}", INDENT, sigAlg);
        logger.info("{} PubKey Alg    : {}", INDENT, pubKeyAlg);

        certInfo.put("subjectDN", subjectDN);
        certInfo.put("issuerDN", issuerDN);
        certInfo.put("version", version);
        certInfo.put("serialNumber", serialNumber);
        certInfo.put("validFrom", validFrom);
        certInfo.put("validUntil", validUntil);
        certInfo.put("signatureAlgorithm", sigAlg);
        certInfo.put("publicKeyAlgorithm", pubKeyAlg);

        addSubjectAlternativeNames(cert, certInfo);
        return certInfo;
    }

    private void addSubjectAlternativeNames(X509Certificate cert, Map<String, Object> certInfo) throws Exception {
        var sans = cert.getSubjectAlternativeNames();
        if (sans != null) {
            logger.info("{} SubjectAltNames:", INDENT);
            Map<String, String> sanMap = new HashMap<>();
            for (var san : sans) {
                Integer type = (Integer) san.get(0);
                String value = (String) san.get(1);
                logger.info("{}   • {}: {}", INDENT, type, value);
                sanMap.put(type.toString(), value);
            }
            certInfo.put("subjectAlternativeNames", sanMap);
        }
    }

    public boolean verifyHostname(X509Certificate cert, String hostname) {
        try {
            // Check Subject Alternative Names first
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (var san : sans) {
                    Integer type = (Integer) san.get(0);
                    String value = (String) san.get(1);
                    
                    // DNS type = 2
                    if (type == 2 && matchesHostname(value, hostname)) {
                        return true;
                    }
                }
            }

            // Fallback to Common Name in Subject DN
            String subjectDN = cert.getSubjectX500Principal().getName();
            String[] parts = subjectDN.split(",");
            for (String part : parts) {
                if (part.startsWith("CN=")) {
                    String cn = part.substring(3);
                    if (matchesHostname(cn, hostname)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matchesHostname(String pattern, String hostname) {
        pattern = pattern.toLowerCase();
        hostname = hostname.toLowerCase();

        if (pattern.startsWith("*.")) {
            String patternDomain = pattern.substring(2);
            String hostnameDomain = hostname;
            
            int dotCount = hostname.length() - hostname.replace(".", "").length();
            if (dotCount < 1) {
                return false;
            }
            
            int firstDot = hostname.indexOf('.');
            if (firstDot > 0) {
                hostnameDomain = hostname.substring(firstDot + 1);
            }
            
            return hostnameDomain.equals(patternDomain);
        }
        
        return pattern.equals(hostname);
    }
} 