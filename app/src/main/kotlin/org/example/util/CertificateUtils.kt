package org.example.util

import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

object CertificateUtils {
    fun getCertificateSubject(certificate: X509Certificate): String {
        return certificate.subjectX500Principal.toString()
    }

    fun getCertificateIssuer(certificate: X509Certificate): String {
        return certificate.issuerX500Principal.toString()
    }

    fun getCertificateValidityPeriod(certificate: X509Certificate): String {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        return """
            Not Before: ${dateFormat.format(certificate.notBefore)}
            Not After: ${dateFormat.format(certificate.notAfter)}
        """.trimIndent()
    }

    fun getCertificateSerialNumber(certificate: X509Certificate): String {
        return certificate.serialNumber.toString(16).uppercase()
    }
} 