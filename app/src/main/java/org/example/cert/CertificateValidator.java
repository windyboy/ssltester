package org.example.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages SSL/TLS certificate validation processes.
 * This class is responsible for validating server certificate chains against a truststore,
 * including performing revocation checks (if OCSP/CRL information is available and checking is enabled).
 * It also extracts detailed information from X.509 certificates and performs hostname
 * verification against the certificate's Subject Alternative Names (SANs) or Common Name (CN).
 */
public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final String INDENT = "   ";

    private final File keystoreFile;
    private final String keystorePassword;

    /**
     * Constructs a CertificateValidator.
     *
     * @param keystoreFile     The custom truststore (keystore) file to be used for validating
     *                         certificate chains. If null, the system's default truststore will be used.
     * @param keystorePassword The password for the custom truststore file. This is ignored if
     *                         {@code keystoreFile} is null.
     */
    public CertificateValidator(File keystoreFile, String keystorePassword) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
    }

    /**
     * Validates the provided server certificate chain.
     * It uses a PKIX TrustManagerFactory with revocation checking enabled.
     *
     * @param certs              The server's certificate chain as an array of {@link Certificate}.
     * @param authTypeFromCipher The key exchange algorithm string (e.g., "RSA", "EC") derived from the
     *                           cipher suite. This is used by the TrustManager to ensure the
     *                           end-entity certificate's key type is appropriate for the cipher.
     * @return The validated certificate chain as an array of {@link X509Certificate}.
     * @throws CertificateException If the certificate chain validation fails for any reason,
     *                              including trust issues, revocation failure, or incorrect key type.
     */
    public X509Certificate[] validateCertificateChain(Certificate[] certs, String authTypeFromCipher) throws CertificateException {
        X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);

        // authTypeFromCipher is now passed as a parameter
        // String sigAlg = x509Certs[0].getSigAlgName(); // Removed
        // String auth = determineAuthType(sigAlg); // Removed

        tm.checkServerTrusted(x509Certs, authTypeFromCipher);
        logger.info("→ Certificate chain trusted using authType: {}", authTypeFromCipher);
        return x509Certs;
    }

    /**
     * Initializes a PKIX {@link TrustManagerFactory} with revocation checking enabled.
     * It configures the factory to use either a custom truststore specified at construction
     * or the system's default truststore if no custom one was provided.
     *
     * @return The initialized {@link TrustManagerFactory}.
     * @throws CertificateException If there's an error initializing the TrustManagerFactory,
     *                              loading the keystore, or configuring the PKIX parameters.
     */
    private TrustManagerFactory initializeTrustManagerFactory() throws CertificateException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            PKIXBuilderParameters pkixParams;

            if (keystoreFile != null) {
                logger.debug("Using custom keystore: {}", keystoreFile.getAbsolutePath());
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                try (InputStream fis = new FileInputStream(keystoreFile)) {
                    ks.load(fis, keystorePassword != null ? keystorePassword.toCharArray() : null);
                }
                pkixParams = new PKIXBuilderParameters(ks, new X509CertSelector());
            } else {
                logger.debug("Using system default truststore.");
                KeyStore systemTrustStore = getSystemTrustStore();
                pkixParams = new PKIXBuilderParameters(systemTrustStore, new X509CertSelector());
            }

            pkixParams.setRevocationEnabled(true);
            logger.debug("Revocation checking enabled in PKIXBuilderParameters.");

            tmf.init(new CertPathTrustManagerParameters(pkixParams));
            return tmf;
        } catch (Exception e) {
            throw new CertificateException("Failed to initialize PKIX trust manager: " + e.getMessage(), e);
        }
    }

    /**
     * Loads the default system truststore (either 'jssecacerts' or 'cacerts' from the JRE's security directory).
     *
     * @return The loaded {@link KeyStore} object representing the system truststore.
     * @throws CertificateException If the truststore file cannot be found, loaded, or if there's a KeyStore error.
     */
    private KeyStore getSystemTrustStore() throws CertificateException {
        try {
            String javaHome = System.getProperty("java.home");
            Path trustStorePath = Paths.get(javaHome, "lib", "security", "jssecacerts");
            if (!Files.exists(trustStorePath)) {
                trustStorePath = Paths.get(javaHome, "lib", "security", "cacerts");
            }

            if (!Files.exists(trustStorePath)) {
                throw new CertificateException("Could not find jssecacerts or cacerts in " + javaHome);
            }
            logger.debug("Loading system truststore from: {}", trustStorePath);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream fis = Files.newInputStream(trustStorePath)) {
                // Default password for cacerts is "changeit"
                trustStore.load(fis, "changeit".toCharArray());
            }
            return trustStore;
        } catch (KeyStoreException e) {
             throw new CertificateException("Failed to instantiate KeyStore for system truststore: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateException("Failed to load system truststore: " + e.getMessage(), e);
        }
    }

    /**
     * Finds and returns an {@link X509TrustManager} from the provided {@link TrustManagerFactory}.
     *
     * @param tmf The {@link TrustManagerFactory} from which to extract the trust manager.
     * @return The first {@link X509TrustManager} found.
     * @throws CertificateException If no X509TrustManager is found in the factory.
     */
    private X509TrustManager findX509TrustManager(TrustManagerFactory tmf) throws CertificateException {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new CertificateException("No X509TrustManager found");
    }

    // private String determineAuthType(String sigAlg) { // Method removed
    //     String auth = sigAlg.substring(sigAlg.toUpperCase().indexOf("WITH") + 4);
    //     return "ECDSA".equalsIgnoreCase(auth) ? "ECDHE_ECDSA" : auth;
    // }

    /**
     * Extracts detailed information from a given X.509 certificate.
     * Information includes Subject DN, Issuer DN, version, serial number, validity period,
     * signature algorithm, public key algorithm, and Subject Alternative Names (SANs).
     *
     * @param cert The {@link X509Certificate} to extract information from.
     * @return A {@link Map} where keys are descriptive strings (e.g., "subjectDN", "serialNumber")
     *         and values are the corresponding certificate details.
     * @throws Exception If there's an error parsing the certificate (e.g., {@link java.security.cert.CertificateEncodingException}).
     */
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

    /**
     * Extracts Subject Alternative Names (SANs) from the certificate and adds them to the provided {@code certInfo} map.
     * Logs the extracted SANs.
     *
     * @param cert The {@link X509Certificate} from which to extract SANs.
     * @param certInfo The {@link Map} to which the extracted SANs will be added under the key "subjectAlternativeNames".
     * @throws Exception If an error occurs during the parsing of SANs (e.g., {@link java.security.cert.CertificateParsingException}).
     */
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

    /**
     * Verifies if the given hostname matches the Common Name (CN) or any of the Subject Alternative Names (SANs)
     * present in the provided X.509 certificate.
     * The method prioritizes SANs (DNS type) over CN for matching.
     *
     * @param cert     The server's end-entity {@link X509Certificate}.
     * @param hostname The hostname to verify against the certificate.
     * @return {@code true} if the hostname matches a SAN DNSName or the CN in the certificate, {@code false} otherwise.
     */
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
            logger.warn("Hostname verification for '{}' encountered an unexpected error: {}. Returning false.", hostname, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Matches a given hostname against a pattern, which can be an exact domain name or a wildcard domain name.
     * Wildcard logic:
     * <ul>
     *   <li>A pattern like "*.example.com" matches "www.example.com" but not "example.com" or "sub.www.example.com".</li>
     *   <li>The wildcard '*' must represent a single domain label and cannot include dots.</li>
     *   <li>Patterns like "*" or "*." are considered invalid.</li>
     *   <li>Matching is case-insensitive.</li>
     * </ul>
     *
     * @param pattern  The pattern from the certificate's SAN or CN (e.g., "example.com", "*.example.com").
     * @param hostname The hostname to match against the pattern.
     * @return {@code true} if the hostname matches the pattern, {@code false} otherwise.
     */
    private boolean matchesHostname(String pattern, String hostname) {
        logger.debug("Attempting to match pattern '{}' with hostname '{}'", pattern, hostname);
        pattern = pattern.toLowerCase();
        hostname = hostname.toLowerCase();

        // Pattern * should not be considered a valid wildcard
        if (pattern.equals("*")) {
            logger.debug("Pattern '{}' did not match hostname '{}' (wildcard '*' is invalid)", pattern, hostname);
            return false;
        }

        if (pattern.startsWith("*.")) {
            String patternDomain = pattern.substring(2);
            // Ensure patternDomain is not empty and is a valid domain itself (e.g. not just "*.")
            if (patternDomain.isEmpty() || patternDomain.startsWith("*") || patternDomain.contains("*")) {
                 logger.debug("Pattern '{}' did not match hostname '{}' (invalid wildcard pattern domain)", pattern, hostname);
                return false;
            }

            // The part of the hostname matched by the wildcard (*) must not contain any dots.
            int firstDotInHostname = hostname.indexOf('.');
            if (firstDotInHostname == -1) { // No dots in hostname, cannot match *.domain
                logger.debug("Pattern '{}' did not match hostname '{}' (hostname has no dots for wildcard match)", pattern, hostname);
                return false;
            }

            String hostnamePrefix = hostname.substring(0, firstDotInHostname);
            if (hostnamePrefix.contains(".")) { // Wildcard part contains a dot
                logger.debug("Pattern '{}' did not match hostname '{}' (wildcard part contains dots)", pattern, hostname);
                return false;
            }
            
            String hostnameDomain = hostname.substring(firstDotInHostname + 1);
            
            if (hostnameDomain.equals(patternDomain)) {
                logger.debug("Pattern '{}' matched hostname '{}' (wildcard match)", pattern, hostname);
                return true;
            }
        } else if (pattern.equals(hostname)) { // Exact match
            logger.debug("Pattern '{}' matched hostname '{}' (exact match)", pattern, hostname);
            return true;
        }
        
        logger.debug("Pattern '{}' did not match hostname '{}'", pattern, hostname);
        return false;
    }
}