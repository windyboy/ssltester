package org.example.cert;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CertificateValidatorTest {
    private CertificateValidator validator;
    private File keystoreFile;
    private static final String KEYSTORE_PASSWORD = "password";
    private KeyPair keyPair;
    private X509Certificate testCertificate;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws Exception {
        // Create a test keystore
        keystoreFile = new File(tempDir, "test.jks");
        createTestKeystore();
        validator = new CertificateValidator(keystoreFile, KEYSTORE_PASSWORD);
        
        // Generate test certificate
        keyPair = TestCertificateGenerator.generateKeyPair();
        testCertificate = TestCertificateGenerator.generateCertificate(
            "CN=example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair
        );

        // Add the certificate to the keystore
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(keystoreFile.toURI().toURL().openStream(), KEYSTORE_PASSWORD.toCharArray());
        ks.setCertificateEntry("test-cert", testCertificate);
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    private void createTestKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    @Test
    void testValidateCertificateChain_WithValidCertificates() throws Exception {
        // Create test certificates
        Certificate[] certs = new Certificate[]{testCertificate};
        
        // Test validation
        X509Certificate[] validatedCerts = validator.validateCertificateChain(certs);
        
        assertNotNull(validatedCerts);
        assertEquals(certs.length, validatedCerts.length);
    }

    @Test
    void testValidateCertificateChain_WithInvalidCertificates() {
        // Create invalid certificates
        Certificate[] invalidCerts = new Certificate[0];
        
        // Test validation
        assertThrows(CertificateException.class, () -> 
            validator.validateCertificateChain(invalidCerts)
        );
    }

    @Test
    void testGetCertificateInfo() throws Exception {
        // Get certificate info
        Map<String, Object> certInfo = validator.getCertificateInfo(testCertificate);
        
        // Verify the info
        assertNotNull(certInfo);
        assertTrue(certInfo.containsKey("subjectDN"));
        assertTrue(certInfo.containsKey("issuerDN"));
        assertTrue(certInfo.containsKey("version"));
        assertTrue(certInfo.containsKey("serialNumber"));
        assertTrue(certInfo.containsKey("validFrom"));
        assertTrue(certInfo.containsKey("validUntil"));
        assertTrue(certInfo.containsKey("signatureAlgorithm"));
        assertTrue(certInfo.containsKey("publicKeyAlgorithm"));
    }

    @Test
    void testVerifyHostname_ExactMatch() throws Exception {
        assertTrue(validator.verifyHostname(testCertificate, "example.com"));
    }

    @Test
    void testVerifyHostname_WildcardMatch() throws Exception {
        assertTrue(validator.verifyHostname(testCertificate, "sub.example.com"));
    }

    @Test
    void testVerifyHostname_NoMatch() throws Exception {
        assertFalse(validator.verifyHostname(testCertificate, "other.com"));
    }

    @Test
    void testVerifyHostname_WithSubjectAltNames() throws Exception {
        assertTrue(validator.verifyHostname(testCertificate, "alt.example.com"));
    }
} 