package org.example.cert;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CertificateValidatorTest {

    @Mock
    private X509Certificate mockCert;

    private CertificateValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CertificateValidator(null, null); // Keystore params not needed for hostname verification
    }

    private void mockSans(List<List<?>> sans) throws CertificateParsingException {
        when(mockCert.getSubjectAlternativeNames()).thenReturn(sans);
    }

    private void mockCn(String cn) {
        when(mockCert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=" + cn + ", O=Test Org"));
    }
    
    private void mockCnOnly(String cn) throws CertificateParsingException {
        when(mockCert.getSubjectAlternativeNames()).thenReturn(null); // Ensure SANs are null
        when(mockCert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=" + cn + ", O=Test Org"));
    }
    
    private void mockNoSansAndNoCn() throws CertificateParsingException {
        when(mockCert.getSubjectAlternativeNames()).thenReturn(null);
        when(mockCert.getSubjectX500Principal()).thenReturn(new X500Principal("O=Test Org")); // No CN
    }


    @Test
    void testVerifyHostname_ExactSANMatch() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "example.com")));
        assertTrue(validator.verifyHostname(mockCert, "example.com"));
    }

    @Test
    void testVerifyHostname_WildcardSANMatch() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.example.org")));
        assertTrue(validator.verifyHostname(mockCert, "test.example.org"));
    }

    @Test
    void testVerifyHostname_WildcardSANNoSubdomainMatch() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.example.org")));
        assertFalse(validator.verifyHostname(mockCert, "example.org"));
    }

    @Test
    void testVerifyHostname_WildcardSANMultipleLevelsNoMatch() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.example.org")));
        assertFalse(validator.verifyHostname(mockCert, "foo.bar.example.org"));
    }
    
    @Test
    void testVerifyHostname_HostnamePartMatchedByWildcardContainsDot() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.example.com")));
        assertFalse(validator.verifyHostname(mockCert, "foo.bar.example.com"), 
                    "Should be false because 'foo.bar' contains a dot");
    }

    @Test
    void testVerifyHostname_ExactCNMatch() throws Exception {
        mockCnOnly("test.example.com");
        assertTrue(validator.verifyHostname(mockCert, "test.example.com"));
    }

    @Test
    void testVerifyHostname_WildcardCNMatch() throws Exception {
        mockCnOnly("*.example.com");
        assertTrue(validator.verifyHostname(mockCert, "test.example.com"));
    }

    @Test
    void testVerifyHostname_NoMatchSANOrCN() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "other.com")));
        mockCn("another.com");
        assertFalse(validator.verifyHostname(mockCert, "test.example.com"));
    }
    
    @Test
    void testVerifyHostname_NoMatchWithNoSansAndNoCnInSubject() throws Exception {
        mockNoSansAndNoCn();
        assertFalse(validator.verifyHostname(mockCert, "test.example.com"));
    }

    @Test
    void testVerifyHostname_SANPreferredOverCN() throws Exception {
        List<List<?>> sans = new ArrayList<>();
        sans.add(Arrays.asList(2, "san.example.com"));
        mockSans(sans);
        mockCn("cn.example.com"); // This CN should not be used if SAN matches
        assertTrue(validator.verifyHostname(mockCert, "san.example.com"));
        assertFalse(validator.verifyHostname(mockCert, "cn.example.com"));
    }

    @Test
    void testVerifyHostname_InvalidWildcardPatternInSAN_StarOnly() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*")));
        mockCn("cn.example.com"); // Fallback CN
        // Depending on strictness, "*" might match "cn.example.com" if CN is checked.
        // Current logic: invalid wildcard '*' in SAN will not match, then CN is checked.
        assertTrue(validator.verifyHostname(mockCert, "cn.example.com"), "Should match CN as SAN wildcard '*' is invalid");
        assertFalse(validator.verifyHostname(mockCert, "any.other.host"), "Should not match anything if SAN is '*' and CN doesn't match");
    }
    
    @Test
    void testVerifyHostname_InvalidWildcardPatternInSAN_StarDot() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.")));
        mockCn("cn.example.com");
        assertTrue(validator.verifyHostname(mockCert, "cn.example.com"), "Should match CN as SAN wildcard '*.' is invalid");
    }


    @Test
    void testVerifyHostname_InvalidWildcardPatternInCN_StarOnly() throws Exception {
        mockCnOnly("*");
        assertFalse(validator.verifyHostname(mockCert, "test.example.com"), "CN '*' should not match");
    }
    
    @Test
    void testVerifyHostname_InvalidWildcardPatternInCN_StarDot() throws Exception {
        mockCnOnly("*.");
        assertFalse(validator.verifyHostname(mockCert, "test.example.com"), "CN '*.' should not match");
    }


    @Test
    void testVerifyHostname_CaseInsensitiveMatchSAN() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "ExAmPlE.CoM")));
        assertTrue(validator.verifyHostname(mockCert, "example.com"));
        assertTrue(validator.verifyHostname(mockCert, "EXAMPLE.COM"));
    }

    @Test
    void testVerifyHostname_CaseInsensitiveMatchCN() throws Exception {
        mockCnOnly("TeSt.ExAmPlE.OrG");
        assertTrue(validator.verifyHostname(mockCert, "test.example.org"));
        assertTrue(validator.verifyHostname(mockCert, "TEST.EXAMPLE.ORG"));
    }
    
    @Test
    void testVerifyHostname_WildcardSANCaseInsensitive() throws Exception {
        mockSans(Collections.singletonList(Arrays.asList(2, "*.ExAmPlE.oRg")));
        assertTrue(validator.verifyHostname(mockCert, "TeSt.example.org"));
    }

    @Test
    void testVerifyHostname_IPAddressSANNoMatch_Type7() throws Exception {
        // Current implementation only checks DNSName (type 2)
        // This test confirms that other types like IPAddress (type 7) are ignored by current logic
        List<List<?>> sans = new ArrayList<>();
        sans.add(Arrays.asList(7, "192.168.1.1")); // IPAddress type
        sans.add(Arrays.asList(2, "dns.example.com")); // A DNS entry
        mockSans(sans);
        
        assertFalse(validator.verifyHostname(mockCert, "192.168.1.1"), "Should not match IP SAN type 7 with current logic");
        assertTrue(validator.verifyHostname(mockCert, "dns.example.com"), "Should match DNS SAN type 2");
    }

    @Test
    void testVerifyHostname_SANWithNullValue() throws Exception {
        List<List<?>> sans = new ArrayList<>();
        sans.add(Arrays.asList(2, null)); // Null DNSName
        sans.add(Arrays.asList(2, "example.com"));
        mockSans(sans);
        assertTrue(validator.verifyHostname(mockCert, "example.com"));
    }
    
    @Test
    void testVerifyHostname_MalformedCN() throws Exception {
        // Test with a CN that doesn't have "CN=" prefix or is otherwise malformed
        when(mockCert.getSubjectAlternativeNames()).thenReturn(null);
        when(mockCert.getSubjectX500Principal()).thenReturn(new X500Principal("OU=OrgUnit, O=Test Org"));
        assertFalse(validator.verifyHostname(mockCert, "test.example.com"));
    }

    @Test
    void testVerifyHostname_WildcardSANMatchingSecondLevelDomain() throws Exception {
        // *.example.org should match test.example.org but not example.org
        mockSans(Collections.singletonList(Arrays.asList(2, "*.example.org")));
        assertTrue(validator.verifyHostname(mockCert, "foo.example.org"));
        assertFalse(validator.verifyHostname(mockCert, "example.org"));
    }

    @Test
    void testVerifyHostname_WildcardCNMatchingSecondLevelDomain() throws Exception {
        // *.example.org should match test.example.org but not example.org (when no SANs)
        mockCnOnly("*.example.org");
        assertTrue(validator.verifyHostname(mockCert, "foo.example.org"));
        assertFalse(validator.verifyHostname(mockCert, "example.org"));
    }
    
    @Test
    void testVerifyHostname_InternationalizedDomainName_SAN_Exact() throws Exception {
        // Example: xn--fsqu00a.xn--0zwm56d is equivalent to 你好.中国
        // Current logic should work fine as it's string matching
        String idn = "xn--fsqu00a.xn--0zwm56d";
        String unicodeIdn = "你好.中国"; // For reference, not used in mock
        mockSans(Collections.singletonList(Arrays.asList(2, idn)));
        assertTrue(validator.verifyHostname(mockCert, idn));
    }

    @Test
    void testVerifyHostname_InternationalizedDomainName_CN_Exact() throws Exception {
        String idn = "xn--ls8h.example.com"; // bücher.example.com
        mockCnOnly(idn);
        assertTrue(validator.verifyHostname(mockCert, idn));
    }

    @Test
    void testVerifyHostname_InternationalizedDomainName_SAN_Wildcard() throws Exception {
        String idnPattern = "*.xn--0zwm56d"; // *.中国
        String idnMatch = "xn--fsqu00a.xn--0zwm56d"; // 你好.中国
        mockSans(Collections.singletonList(Arrays.asList(2, idnPattern)));
        assertTrue(validator.verifyHostname(mockCert, idnMatch));
    }
}
