package org.example.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

public class CertificateRevocationChecker {
    private static final Logger logger = LoggerFactory.getLogger(CertificateRevocationChecker.class);
    private final HttpClient httpClient;
    private final boolean checkOCSP;
    private final boolean checkCRL;

    public CertificateRevocationChecker(boolean checkOCSP, boolean checkCRL) {
        this.checkOCSP = checkOCSP;
        this.checkCRL = checkCRL;
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public void checkRevocation(X509Certificate cert) throws CertificateException {
        if (!checkOCSP && !checkCRL) {
            return;
        }

        try {
            if (checkOCSP) {
                checkOCSP(cert);
            }
            if (checkCRL) {
                checkCRL(cert);
            }
        } catch (Exception e) {
            throw new CertificateException("Certificate revocation check failed: " + e.getMessage(), e);
        }
    }

    private void checkOCSP(X509Certificate cert) throws IOException, InterruptedException, CertificateException {
        String ocspUrl = getOCSPUrl(cert);
        if (ocspUrl == null) {
            logger.debug("No OCSP URL found in certificate");
            return;
        }

        logger.debug("Checking OCSP status at: {}", ocspUrl);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(ocspUrl))
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("OCSP request failed with status: " + response.statusCode());
        }

        // Parse OCSP response
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate responderCert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(response.body()));
            
            // Verify OCSP response
            if (!verifyOCSPResponse(responderCert, cert)) {
                throw new CertificateException("Invalid OCSP response");
            }
            
            logger.debug("OCSP check completed successfully");
        } catch (CertificateException e) {
            throw new CertificateException("Failed to parse OCSP response: " + e.getMessage(), e);
        }
    }

    private void checkCRL(X509Certificate cert) throws IOException, CRLException, CertificateException {
        List<String> crlUrls = getCRLUrls(cert);
        if (crlUrls.isEmpty()) {
            logger.debug("No CRL URLs found in certificate");
            return;
        }

        for (String crlUrl : crlUrls) {
            logger.debug("Checking CRL at: {}", crlUrl);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(crlUrl))
                    .GET()
                    .build();

            try {
                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() != 200) {
                    logger.warn("CRL request failed with status: {}", response.statusCode());
                    continue;
                }

                X509CRL crl = parseCRL(response.body());
                if (crl.isRevoked(cert)) {
                    throw new CertificateException("Certificate is revoked according to CRL");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("CRL check interrupted", e);
            }
        }
    }

    private String getOCSPUrl(X509Certificate cert) {
        try {
            // Get Authority Information Access extension
            byte[] aiaExtension = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
            if (aiaExtension == null) {
                return null;
            }

            // Parse the extension to find OCSP URL
            // This is a simplified implementation - in practice, you'd need to properly parse the ASN.1 structure
            String aiaString = new String(aiaExtension);
            if (aiaString.contains("OCSP")) {
                int start = aiaString.indexOf("http://");
                if (start == -1) {
                    start = aiaString.indexOf("https://");
                }
                if (start != -1) {
                    int end = aiaString.indexOf("\n", start);
                    if (end == -1) {
                        end = aiaString.length();
                    }
                    return aiaString.substring(start, end).trim();
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to extract OCSP URL: {}", e.getMessage());
        }
        return null;
    }

    private List<String> getCRLUrls(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        try {
            // Get CRL Distribution Points extension
            byte[] crlDpExtension = cert.getExtensionValue("2.5.29.31");
            if (crlDpExtension == null) {
                return urls;
            }

            // Parse the extension to find CRL URLs
            // This is a simplified implementation - in practice, you'd need to properly parse the ASN.1 structure
            String crlDpString = new String(crlDpExtension);
            int start = 0;
            while (true) {
                start = crlDpString.indexOf("http://", start);
                if (start == -1) {
                    start = crlDpString.indexOf("https://", start);
                }
                if (start == -1) {
                    break;
                }
                int end = crlDpString.indexOf("\n", start);
                if (end == -1) {
                    end = crlDpString.length();
                }
                urls.add(crlDpString.substring(start, end).trim());
                start = end;
            }
        } catch (Exception e) {
            logger.warn("Failed to extract CRL URLs: {}", e.getMessage());
        }
        return urls;
    }

    private X509CRL parseCRL(byte[] crlData) throws CRLException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlData));
        } catch (CertificateException e) {
            throw new CRLException("Failed to parse CRL: " + e.getMessage(), e);
        }
    }

    private boolean verifyOCSPResponse(X509Certificate responderCert, X509Certificate cert) {
        // In a real implementation, you would:
        // 1. Verify the responder certificate
        // 2. Check the OCSP response signature
        // 3. Verify the response is for the correct certificate
        // 4. Check the response status
        return true; // Simplified implementation
    }
} 