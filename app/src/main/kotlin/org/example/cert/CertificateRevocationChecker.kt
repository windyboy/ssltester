package org.example.cert

import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.cert.CRLException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.math.BigInteger

class CertificateRevocationChecker(
    private val checkOCSP: Boolean,
    private val checkCRL: Boolean,
    private val failOnError: Boolean = true
) {
    private val logger = LoggerFactory.getLogger(CertificateRevocationChecker::class.java)
    private val httpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    /**
     * Checks if a certificate has been revoked using OCSP.
     * @param cert The certificate to check
     * @throws CertificateException if the certificate is revoked or there's an error checking revocation
     */
    @Throws(CertificateException::class)
    fun checkRevocation(cert: X509Certificate) {
        if (!checkOCSP) {
            return
        }

        try {
            val ocspUrl = getOCSPUrl(cert)
            if (ocspUrl == null) {
                logger.debug("No OCSP responder URL found for certificate: {}", cert.subjectX500Principal)
                return
            }

            val request = generateOCSPRequest(cert)
            val response = sendOCSPRequest(ocspUrl, request)
            validateOCSPResponse(response, cert)
        } catch (e: Exception) {
            logger.warn("OCSP check failed: {}", e.message)
            if (failOnError) {
                throw CertificateException("OCSP check failed: ${e.message}", e)
            }
        }
    }

    /**
     * Generates an OCSP request for the given certificate.
     * @param cert The certificate to check
     * @return The generated OCSP request as a byte array
     */
    private fun generateOCSPRequest(cert: X509Certificate): ByteArray {
        try {
            val digestCalculator = JcaDigestCalculatorProviderBuilder()
                .build()
                .get(CertificateID.HASH_SHA1)

            val certId = CertificateID(
                digestCalculator,
                X509CertificateHolder(cert.encoded),
                BigInteger.valueOf(cert.serialNumber.toLong())
            )

            val requestGenerator = OCSPReqBuilder()
            requestGenerator.addRequest(certId)

            return requestGenerator.build().encoded
        } catch (e: Exception) {
            throw CertificateException("Failed to generate OCSP request: ${e.message}", e)
        }
    }

    /**
     * Sends an OCSP request to the specified URL.
     * @param url The OCSP responder URL
     * @param request The OCSP request to send
     * @return The OCSP response as a byte array
     */
    private fun sendOCSPRequest(url: String, request: ByteArray): ByteArray {
        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/ocsp-request")
            .POST(HttpRequest.BodyPublishers.ofByteArray(request))
            .build()

        try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray())
            if (response.statusCode() != 200) {
                throw IOException("OCSP request failed with status: ${response.statusCode()}")
            }
            return response.body()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("OCSP request interrupted", e)
        }
    }

    /**
     * Validates an OCSP response for a given certificate.
     * @param response The OCSP response to validate
     * @param cert The certificate being checked
     * @throws CertificateException if the response is invalid or indicates revocation
     */
    @Throws(CertificateException::class)
    private fun validateOCSPResponse(response: ByteArray, cert: X509Certificate) {
        val ocspResp = OCSPResp(response)
        val responseStatus = ocspResp.status
        if (responseStatus != 0) {
            throw CertificateException("OCSP response status: $responseStatus")
        }

        val responseData = ocspResp.responseObject as BasicOCSPResp
        val responses = responseData.responses
        if (responses.isEmpty()) {
            throw CertificateException("No responses in OCSP response")
        }

        val singleResp = responses[0]
        val certStatus = singleResp.certStatus
        if (certStatus != null) {
            throw CertificateException("Certificate is revoked: $certStatus")
        }

        // Verify that the response is for the correct certificate
        val certId = singleResp.certID
        val digestCalculator = JcaDigestCalculatorProviderBuilder()
            .build()
            .get(CertificateID.HASH_SHA1)
        val expectedCertId = CertificateID(
            digestCalculator,
            X509CertificateHolder(cert.encoded),
            BigInteger.valueOf(cert.serialNumber.toLong())
        )
        if (certId != expectedCertId) {
            throw CertificateException("OCSP response is for a different certificate")
        }

        logger.info("Certificate is not revoked according to OCSP")
    }

    private fun checkCRL(cert: X509Certificate) {
        val crlUrls = getCRLUrls(cert)
        if (crlUrls.isEmpty()) {
            logger.debug("No CRL URLs found in certificate")
            return
        }

        for (crlUrl in crlUrls) {
            logger.debug("Checking CRL at: {}", crlUrl)
            val request = HttpRequest.newBuilder()
                .uri(URI.create(crlUrl))
                .GET()
                .build()

            try {
                val response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray())
                if (response.statusCode() != 200) {
                    logger.warn("CRL request failed with status: {}", response.statusCode())
                    continue
                }

                val crl = parseCRL(response.body())
                if (crl.isRevoked(cert)) {
                    throw CertificateException("Certificate is revoked according to CRL")
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("CRL check interrupted", e)
            }
        }
    }

    private fun getOCSPUrl(cert: X509Certificate): String? {
        try {
            // Get Authority Information Access extension
            val aiaExtension = cert.getExtensionValue("1.3.6.1.5.5.7.1.1") ?: return null

            // Parse the extension to find OCSP URL
            // This is a simplified implementation - in practice, you'd need to properly parse the ASN.1 structure
            val aiaString = String(aiaExtension)
            if (aiaString.contains("OCSP")) {
                var start = aiaString.indexOf("http://")
                if (start == -1) {
                    start = aiaString.indexOf("https://")
                }
                if (start != -1) {
                    var end = aiaString.indexOf("\n", start)
                    if (end == -1) {
                        end = aiaString.length
                    }
                    return aiaString.substring(start, end).trim()
                }
            }
        } catch (e: Exception) {
            logger.warn("Failed to extract OCSP URL: {}", e.message)
        }
        return null
    }

    private fun getCRLUrls(cert: X509Certificate): List<String> {
        val urls = mutableListOf<String>()
        try {
            // Get CRL Distribution Points extension
            val crlDpExtension = cert.getExtensionValue("2.5.29.31") ?: return urls

            // Parse the extension to find CRL URLs
            // This is a simplified implementation - in practice, you'd need to properly parse the ASN.1 structure
            val crlDpString = String(crlDpExtension)
            var start = 0
            while (true) {
                start = crlDpString.indexOf("http://", start)
                if (start == -1) {
                    start = crlDpString.indexOf("https://", start)
                }
                if (start == -1) {
                    break
                }
                var end = crlDpString.indexOf("\n", start)
                if (end == -1) {
                    end = crlDpString.length
                }
                urls.add(crlDpString.substring(start, end).trim())
                start = end
            }
        } catch (e: Exception) {
            logger.warn("Failed to extract CRL URLs: {}", e.message)
        }
        return urls
    }

    private fun parseCRL(crlData: ByteArray): X509CRL {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCRL(ByteArrayInputStream(crlData)) as X509CRL
        } catch (e: CertificateException) {
            throw CRLException("Failed to parse CRL: ${e.message}", e)
        }
    }

    private fun verifyOCSPResponse(responderCert: X509Certificate, cert: X509Certificate): Boolean {
        // In a real implementation, you would:
        // 1. Verify the responder certificate
        // 2. Check the OCSP response signature
        // 3. Verify the response is for the correct certificate
        // 4. Check the response status
        logger.debug("Verifying OCSP response from responder {} for certificate {}", 
            responderCert.subjectX500Principal, cert.subjectX500Principal)
        return true // Simplified implementation
    }
} 