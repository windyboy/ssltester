package org.example.util

import java.security.cert.X509Certificate
import java.text.SimpleDateFormat

object CertificateUtils {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    fun getCertificateSubject(certificate: X509Certificate): String {
        return certificate.subjectX500Principal.toString()
    }

    fun getCertificateIssuer(certificate: X509Certificate): String {
        return certificate.issuerX500Principal.toString()
    }

    fun getCertificateValidityPeriod(certificate: X509Certificate): String {
        val notBefore = dateFormat.format(certificate.notBefore)
        val notAfter = dateFormat.format(certificate.notAfter)
        return "Not Before: $notBefore, Not After: $notAfter"
    }

    fun getCertificateSerialNumber(certificate: X509Certificate): String {
        return certificate.serialNumber.toString(16).uppercase()
    }
} 