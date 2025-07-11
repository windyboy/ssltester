package org.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate

class CertificateValidator {
    data class ValidationResult(
        val isValid: Boolean,
        val revocationStatus: RevocationStatus,
        val errors: List<String> = emptyList(),
    )

    sealed class RevocationStatus {
        object Valid : RevocationStatus()

        data class Revoked(val reason: String) : RevocationStatus()

        object Unknown : RevocationStatus()

        data class Error(val message: String) : RevocationStatus()
    }

    suspend fun validateCertificateChain(certificates: List<X509Certificate>): ValidationResult =
        withContext(Dispatchers.IO) {
            if (certificates.isEmpty()) {
                return@withContext ValidationResult(
                    isValid = false,
                    revocationStatus = RevocationStatus.Error("No certificates provided"),
                    errors = listOf("No certificates provided"),
                )
            }

            val errors = mutableListOf<String>()

            // 1. 证书链结构校验
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                val certPath = certFactory.generateCertPath(certificates)
                val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
                trustStore.load(null, null)
                val pkixParams = PKIXParameters(trustStore)
                pkixParams.isRevocationEnabled = false // 只用OCSP
                CertPathValidator.getInstance("PKIX").validate(certPath, pkixParams)
            } catch (e: Exception) {
                errors.add("Chain validation failed: ${e.message}")
                return@withContext ValidationResult(
                    isValid = false,
                    revocationStatus = RevocationStatus.Error(e.message ?: "Chain validation failed"),
                    errors = errors,
                )
            }

            // 2. OCSP 检查
            val leaf = certificates[0]
            val issuer = certificates.getOrNull(1) ?: certificates[0]
            val ocspUrl = getOcspUrl(leaf)

            if (ocspUrl == null) {
                return@withContext ValidationResult(
                    isValid = true,
                    revocationStatus = RevocationStatus.Unknown,
                    errors = errors,
                )
            }

            try {
                val certId =
                    CertificateID(
                        JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                        JcaX509CertificateHolder(issuer),
                        leaf.serialNumber,
                    )

                val reqGen = OCSPReqBuilder()
                reqGen.addRequest(certId)
                val ocspReq = reqGen.build()

                val conn = URL(ocspUrl).openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/ocsp-request")
                conn.setRequestProperty("Accept", "application/ocsp-response")
                conn.doOutput = true
                conn.outputStream.use { it.write(ocspReq.encoded) }

                val responseBytes = conn.inputStream.use { it.readBytes() }
                val resp = OCSPResp(responseBytes)

                if (resp.status != OCSPResp.SUCCESSFUL) {
                    return@withContext ValidationResult(
                        isValid = true,
                        revocationStatus = RevocationStatus.Unknown,
                        errors = errors,
                    )
                }

                val basic =
                    resp.responseObject as? BasicOCSPResp
                        ?: return@withContext ValidationResult(
                            isValid = true,
                            revocationStatus = RevocationStatus.Unknown,
                            errors = errors,
                        )

                val singleResp =
                    basic.responses.firstOrNull()
                        ?: return@withContext ValidationResult(
                            isValid = true,
                            revocationStatus = RevocationStatus.Unknown,
                            errors = errors,
                        )

                when (val status = singleResp.certStatus) {
                    null -> return@withContext ValidationResult(
                        isValid = true,
                        revocationStatus = RevocationStatus.Valid,
                        errors = errors,
                    )
                    is CertificateStatus -> {
                        if (status.javaClass.simpleName == "Revoked") {
                            return@withContext ValidationResult(
                                isValid = false,
                                revocationStatus = RevocationStatus.Revoked("OCSP: revoked"),
                                errors = errors,
                            )
                        } else if (status.javaClass.simpleName == "Unknown") {
                            return@withContext ValidationResult(
                                isValid = true,
                                revocationStatus = RevocationStatus.Unknown,
                                errors = errors,
                            )
                        } else {
                            return@withContext ValidationResult(
                                isValid = true,
                                revocationStatus = RevocationStatus.Unknown,
                                errors = errors,
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                errors.add("OCSP check failed: ${e.message}")
                return@withContext ValidationResult(
                    isValid = true,
                    revocationStatus = RevocationStatus.Error(e.message ?: "OCSP check failed"),
                    errors = errors,
                )
            }
        }

    private fun getOcspUrl(cert: X509Certificate): String? {
        val aiaExt = cert.getExtensionValue("1.3.6.1.5.5.7.1.1") ?: return null
        // 这里建议用 ASN.1 解析库解析出 OCSP URL，简单起见可用第三方工具或正则提取
        // 生产环境请用 ASN.1 解析
        return null // TODO: 实现 ASN.1 解析
    }
}
