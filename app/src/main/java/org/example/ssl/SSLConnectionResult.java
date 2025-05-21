package org.example.ssl;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Collection;

public class SSLConnectionResult {
    private final boolean success;
    private final List<X509Certificate> certificateChain;
    private final Exception error;
    private final String cipherSuite;
    private final int httpStatus;
    private final boolean hostnameVerified;

    public SSLConnectionResult(boolean success, List<X509Certificate> certificateChain, 
                             Exception error, String cipherSuite, int httpStatus, boolean hostnameVerified) {
        this.success = success;
        this.certificateChain = certificateChain;
        this.error = error;
        this.cipherSuite = cipherSuite;
        this.httpStatus = httpStatus;
        this.hostnameVerified = hostnameVerified;
    }

    public boolean isSuccess() {
        return success;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public Exception getError() {
        return error;
    }

    public String getCipherSuite() {
        return cipherSuite;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public boolean isHostnameVerified() {
        return hostnameVerified;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("→ HTTP Status  : ").append(httpStatus).append("\n");
        sb.append("→ Cipher Suite : ").append(cipherSuite).append("\n");
        sb.append("→ Certificate chain ").append(success ? "trusted" : "not trusted").append("\n");
        sb.append("→ Hostname verification ").append(hostnameVerified ? "passed" : "failed").append("\n");
        
        if (certificateChain != null && !certificateChain.isEmpty()) {
            sb.append("→ Server sent ").append(certificateChain.size()).append(" certificate(s):\n");
            for (int i = 0; i < certificateChain.size(); i++) {
                sb.append("\nCertificate [").append(i + 1).append("]\n");
                X509Certificate cert = certificateChain.get(i);
                sb.append("    Subject DN    : ").append(cert.getSubjectX500Principal().getName()).append("\n");
                sb.append("    Issuer DN     : ").append(cert.getIssuerX500Principal().getName()).append("\n");
                sb.append("    Version       : ").append(cert.getVersion()).append("\n");
                sb.append("    Serial Number : ").append(cert.getSerialNumber().toString(16).toUpperCase()).append("\n");
                sb.append("    Valid From    : ").append(cert.getNotBefore()).append("\n");
                sb.append("    Valid Until   : ").append(cert.getNotAfter()).append("\n");
                sb.append("    Sig. Algorithm: ").append(cert.getSigAlgName()).append("\n");
                sb.append("    PubKey Alg    : ").append(cert.getPublicKey().getAlgorithm());
                
                // 添加 Subject Alternative Names 扩展信息
                try {
                    Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                    if (sans != null && !sans.isEmpty()) {
                        sb.append("\n    Subject Alternative Names:\n");
                        for (List<?> san : sans) {
                            Integer type = (Integer) san.get(0);
                            String value = (String) san.get(1);
                            sb.append("        Type ").append(type).append(": ").append(value).append("\n");
                        }
                    }
                } catch (Exception e) {
                    // 忽略无法获取SAN的情况
                }
            }
        }
        
        return sb.toString();
    }
} 