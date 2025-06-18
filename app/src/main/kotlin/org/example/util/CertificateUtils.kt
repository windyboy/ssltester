package org.example.util

import java.security.cert.X509Certificate
import java.time.format.DateTimeFormatter
import java.time.ZoneId

object CertificateUtils {
    private val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

    fun getCertificateSubject(certificate: X509Certificate): String =
        certificate.subjectX500Principal.toString()

    fun getCertificateIssuer(certificate: X509Certificate): String =
        certificate.issuerX500Principal.toString()

    fun getCertificateValidityPeriod(certificate: X509Certificate): String {
        val notBefore = certificate.notBefore.toInstant()
            .atZone(ZoneId.systemDefault())
            .format(dateFormatter)
        val notAfter = certificate.notAfter.toInstant()
            .atZone(ZoneId.systemDefault())
            .format(dateFormatter)
        return "Not Before: $notBefore, Not After: $notAfter"
    }

    fun getCertificateSerialNumber(certificate: X509Certificate): String =
        certificate.serialNumber.toString(16).uppercase()
}
