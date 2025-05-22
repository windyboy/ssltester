package org.example.cert;

import org.example.model.CertificateDetails;
import org.example.model.RevocationStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CertificateRevocationCheckerTests {

    @Mock
    private X509Certificate mockCert;

    private CertificateRevocationChecker checker;

    @BeforeAll
    static void beforeAll() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        // Default checker, can be re-initialized in tests for specific OCSP/CRL settings
        checker = new CertificateRevocationChecker(true, true);
    }

    // --- Helper method to create DEROctetString for an extension ---
    private byte[] createDerOctetString(ASN1Encodable value) throws IOException {
        return new DEROctetString(value).getEncoded();
    }
    
    private byte[] createAuthorityInformationAccessExtension(String ocspUrl) throws IOException {
        AccessDescription ocspAccessDescription = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl))
        );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccessDescription);
        return createDerOctetString(aia);
    }

    private byte[] createCRLDistributionPointsExtension(String... crlUrls) throws IOException {
        DistributionPoint[] distPoints = new DistributionPoint[crlUrls.length];
        for (int i = 0; i < crlUrls.length; i++) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrls[i]));
            GeneralNames gns = new GeneralNames(gn);
            DistributionPointName dpn = new DistributionPointName(DistributionPointName.FULL_NAME, gns);
            distPoints[i] = new DistributionPoint(dpn, null, null);
        }
        CRLDistPoint crlDistPoint = new CRLDistPoint(distPoints);
        return createDerOctetString(crlDistPoint);
    }


    // --- Tests for getOCSPUrl ---
    @Test
    void testGetOCSPUrl_ValidAIA_ReturnsUrl() throws Exception {
        String expectedUrl = "http://ocsp.example.com";
        byte[] aiaExtensionBytes = createAuthorityInformationAccessExtension(expectedUrl);
        when(mockCert.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(aiaExtensionBytes);

        // Reflection or direct call if method is made package-private or public for testing
        // For now, assuming we can call it or test through checkOCSP's initial part.
        // Let's make it package-private for testing.
        // String actualUrl = checker.getOCSPUrl(mockCert); // If made accessible
        // assertEquals(expectedUrl, actualUrl);
        
        // Test via checkOCSP (indirectly) by checking detailsToUpdate.getOcspResponderUrl()
        CertificateDetails details = new CertificateDetails();
        checker.checkRevocation(mockCert, null, details); // issuerCert null will stop full OCSP but URL is extracted
        assertEquals(expectedUrl, details.getOcspResponderUrl());
    }

    @Test
    void testGetOCSPUrl_NoAIAExtension_ReturnsNull() throws Exception {
        when(mockCert.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(null);
        CertificateDetails details = new CertificateDetails();
        checker.checkRevocation(mockCert, null, details);
        assertNull(details.getOcspResponderUrl());
        assertTrue(details.getFailureReason().contains("No OCSP URL found"));
    }
    
    @Test
    void testGetOCSPUrl_AIAWithoutOCSP_ReturnsNull() throws Exception {
        AccessDescription otherAccessDescription = new AccessDescription(
                AccessDescription.id_ad_caIssuers, // Different OID
                new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://caissuer.example.com"))
        );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(otherAccessDescription);
        byte[] aiaExtensionBytes = createDerOctetString(aia);
        when(mockCert.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(aiaExtensionBytes);
        
        CertificateDetails details = new CertificateDetails();
        checker.checkRevocation(mockCert, null, details);
        assertNull(details.getOcspResponderUrl());
         assertTrue(details.getFailureReason().contains("No OCSP URL found"));
    }


    // --- Tests for getCRLUrls ---
    @Test
    void testGetCRLUrls_ValidCRLExtension_ReturnsUrls() throws Exception {
        String[] expectedUrls = {"http://crl1.example.com/crl.crl", "http://crl2.example.com/crl.crl"};
        byte[] crlExtensionBytes = createCRLDistributionPointsExtension(expectedUrls);
        when(mockCert.getExtensionValue(Extension.cRLDistributionPoints.getId())).thenReturn(crlExtensionBytes);

        CertificateDetails details = new CertificateDetails();
        // Call checkRevocation - it will call getCRLUrls internally.
        // We need to ensure OCSP check doesn't fully run or provide a definitive status to allow CRL check to proceed.
        // Disable OCSP for this test to focus on CRL.
        checker = new CertificateRevocationChecker(false, true); 
        checker.checkRevocation(mockCert, null, details); // issuerCert null for CRL is problematic for full check, but URL extraction happens first
        
        assertNotNull(details.getCrlDistributionPoints());
        assertEquals(2, details.getCrlDistributionPoints().size());
        assertTrue(details.getCrlDistributionPoints().contains(expectedUrls[0]));
        assertTrue(details.getCrlDistributionPoints().contains(expectedUrls[1]));
    }

    @Test
    void testGetCRLUrls_NoCRLExtension_ReturnsEmptyList() throws Exception {
        when(mockCert.getExtensionValue(Extension.cRLDistributionPoints.getId())).thenReturn(null);
        checker = new CertificateRevocationChecker(false, true);
        CertificateDetails details = new CertificateDetails();
        checker.checkRevocation(mockCert, null, details);
        
        assertTrue(details.getCrlDistributionPoints() == null || details.getCrlDistributionPoints().isEmpty());
        // Failure reason might indicate no CRL URLs if UNKNOWN status, or be null if NOT_CHECKED
        if (details.getRevocationStatus() == RevocationStatus.UNKNOWN) {
             assertTrue(details.getFailureReason().contains("No CRL URLs found"));
        }
    }
    
    // TODO: Add more complex tests for malformed extensions if possible, though robust ASN.1 parsing is hard to mock simply.

    // --- Tests for checkOCSP logic (simplified due to no HTTP mocking/actual response generation) ---

    @Test
    void testCheckOCSP_NoUrl_SetsUnknown() throws Exception {
        checker = new CertificateRevocationChecker(true, true);
        when(mockCert.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(null); // No OCSP URL
        
        CertificateDetails details = new CertificateDetails();
        // Provide a mock issuer cert, though it won't be used if OCSP URL is null
        X509Certificate mockIssuerCert = Mockito.mock(X509Certificate.class);

        checker.checkOCSP(mockCert, mockIssuerCert, details);
        
        assertEquals(RevocationStatus.UNKNOWN, details.getRevocationStatus());
        assertTrue(details.getFailureReason().contains("No OCSP URL found"));
        assertNull(details.getOcspResponderUrl());
    }

    // Note: Testing full OCSP response processing (GOOD, REVOKED, UNKNOWN status from response bytes)
    // is very complex without actual OCSP response generation tools or pre-saved response files,
    // and mocking the entire HttpURLConnection and Bouncy Castle's parsing.
    // These tests would typically involve:
    // 1. Crafting byte[] for OCSP responses.
    // 2. Mocking HttpURLConnection to return these byte[].
    // 3. Verifying CertificateDetails are updated correctly.
    // For this exercise, we'll acknowledge this limitation. The URL extraction tests provide some coverage.

    // --- Tests for checkCRL logic (simplified) ---

    @Test
    void testCheckCRL_NoUrls_SetsUnknownOrNotChecked() throws Exception {
        checker = new CertificateRevocationChecker(false, true); // OCSP disabled, CRL enabled
        when(mockCert.getExtensionValue(Extension.cRLDistributionPoints.getId())).thenReturn(null); // No CRL URLs
        
        CertificateDetails details = new CertificateDetails();
        X509Certificate mockIssuerCert = Mockito.mock(X509Certificate.class); // Needed for checkCRL signature

        checker.checkCRL(mockCert, mockIssuerCert, details);
        
        // If no URLs, and OCSP was not checked or inconclusive, status should be UNKNOWN with a reason.
        // If OCSP was definitively GOOD/REVOKED, CRL check might be skipped.
        // Here, OCSP is disabled, so CRL is the only check.
        assertEquals(RevocationStatus.UNKNOWN, details.getRevocationStatus());
        assertTrue(details.getCrlDistributionPoints() == null || details.getCrlDistributionPoints().isEmpty());
        assertTrue(details.getFailureReason().contains("No CRL URLs found"));
    }
    
    @Test
    void testCheckCRL_IssuerNotProvided_SetsUnknown() throws Exception {
        checker = new CertificateRevocationChecker(false, true); // OCSP disabled, CRL enabled
        // Simulate having a CRL URL
        String[] crlUrls = {"http://crl.example.com/crl.crl"};
        byte[] crlExtensionBytes = createCRLDistributionPointsExtension(crlUrls);
        when(mockCert.getExtensionValue(Extension.cRLDistributionPoints.getId())).thenReturn(crlExtensionBytes);
        
        CertificateDetails details = new CertificateDetails();
        // Crucially, pass null for issuerCert
        checker.checkCRL(mockCert, null, details); 
        
        assertEquals(RevocationStatus.UNKNOWN, details.getRevocationStatus());
        assertEquals(1, details.getCrlDistributionPoints().size()); // URL is extracted
        assertTrue(details.getFailureReason().contains("CRL check skipped: issuer certificate not available"));
    }

    // Note: Similar to OCSP, testing full CRL processing (download, signature verification, date check, isRevoked)
    // requires either live resources, pre-saved CRL files, and/or extensive HTTP + Bouncy Castle mocking.
    // Acknowledging this limitation.

    // --- Tests for checkRevocation (overall logic) ---

    @Test
    void testCheckRevocation_OCSPDisabledCRLDisabled_SetsNotChecked() {
        checker = new CertificateRevocationChecker(false, false);
        CertificateDetails details = new CertificateDetails();
        // Issuer cert not strictly needed here as checks are disabled
        checker.checkRevocation(mockCert, null, details); 
        
        assertEquals(RevocationStatus.NOT_CHECKED, details.getRevocationStatus());
        assertTrue(details.getFailureReason().contains("Neither OCSP nor CRL checks were enabled"));
    }
    
    @Test
    void testCheckRevocation_OCSPEnabledNoUrl_CRLDisabled_SetsUnknown() throws Exception {
        checker = new CertificateRevocationChecker(true, false); // OCSP on, CRL off
        when(mockCert.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(null); // No OCSP URL
        
        CertificateDetails details = new CertificateDetails();
        X509Certificate mockIssuerCert = Mockito.mock(X509Certificate.class);
        checker.checkRevocation(mockCert, mockIssuerCert, details);
        
        assertEquals(RevocationStatus.UNKNOWN, details.getRevocationStatus());
        assertTrue(details.getFailureReason().contains("No OCSP URL found"));
    }
    
    @Test
    void testCheckRevocation_OCSPDisabled_CRLEnabledNoUrl_SetsUnknown() throws Exception {
        checker = new CertificateRevocationChecker(false, true); // OCSP off, CRL on
        when(mockCert.getExtensionValue(Extension.cRLDistributionPoints.getId())).thenReturn(null); // No CRL URL
        
        CertificateDetails details = new CertificateDetails();
        X509Certificate mockIssuerCert = Mockito.mock(X509Certificate.class);
        checker.checkRevocation(mockCert, mockIssuerCert, details);
        
        assertEquals(RevocationStatus.UNKNOWN, details.getRevocationStatus());
        assertTrue(details.getFailureReason().contains("No CRL URLs found"));
    }

    // Further tests would ideally mock the actual HTTP responses for OCSP and CRL
    // to verify transitions between GOOD, REVOKED, UNKNOWN based on network results.
    // Example (conceptual, needs actual response data and HTTP mocking):
    // @Test
    // void testCheckRevocation_OCSPReturnsGood_CRLSkipped() { ... }
    // @Test
    // void testCheckRevocation_OCSPReturnsRevoked_CRLSkipped() { ... }
    // @Test
    // void testCheckRevocation_OCSPReturnsUnknown_CRLReturnsGood() { ... }
    // @Test
    // void testCheckRevocation_OCSPReturnsUnknown_CRLReturnsRevoked() { ... }
}
