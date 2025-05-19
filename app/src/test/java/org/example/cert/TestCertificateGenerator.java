package org.example.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class TestCertificateGenerator {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int VALIDITY_DAYS = 365;

    public static X509Certificate generateCertificate(String subject, String issuer, 
            KeyPair keyPair, KeyPair issuerKeyPair) throws Exception {
        X500Name subjectDN = new X500Name(subject);
        X500Name issuerDN = new X500Name(issuer);
        
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + VALIDITY_DAYS * 24L * 60 * 60 * 1000);
        
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuerDN,
                serial,
                notBefore,
                notAfter,
                subjectDN,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        
        // Add Subject Alternative Names
        GeneralName[] sans = new GeneralName[] {
            new GeneralName(GeneralName.dNSName, "example.com"),
            new GeneralName(GeneralName.dNSName, "*.example.com"),
            new GeneralName(GeneralName.dNSName, "alt.example.com")
        };
        certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        
        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(issuerKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        
        // Convert to X509Certificate
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
} 