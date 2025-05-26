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
        return generateCertificate(subject, issuer, keyPair, issuerKeyPair, null, null);
    }

    public static X509Certificate generateCertificate(String subject, String issuer,
            KeyPair keyPair, KeyPair issuerKeyPair,
            String[] additionalDnsNames, String[] ipAddresses) throws Exception {
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
        
        // 计算General Names的数量
        int baseCount = 3; // 基本的SAN条目
        int additionalDnsCount = additionalDnsNames != null ? additionalDnsNames.length : 0;
        int ipAddressCount = ipAddresses != null ? ipAddresses.length : 0;
        int totalCount = baseCount + additionalDnsCount + ipAddressCount;

        GeneralName[] sans = new GeneralName[totalCount];

        // 添加基本的DNS名称
        sans[0] = new GeneralName(GeneralName.dNSName, "example.com");
        sans[1] = new GeneralName(GeneralName.dNSName, "*.example.com");
        sans[2] = new GeneralName(GeneralName.dNSName, "alt.example.com");

        // 添加额外的DNS名称
        if (additionalDnsNames != null) {
            for (int i = 0; i < additionalDnsNames.length; i++) {
                sans[baseCount + i] = new GeneralName(GeneralName.dNSName, additionalDnsNames[i]);
            }
        }

        // 添加IP地址
        if (ipAddresses != null) {
            for (int i = 0; i < ipAddresses.length; i++) {
                sans[baseCount + additionalDnsCount + i] = new GeneralName(GeneralName.iPAddress, ipAddresses[i]);
            }
        }

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

