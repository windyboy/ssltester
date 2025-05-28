package org.example.cert

import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.net.InetAddress
import java.net.UnknownHostException

class TestCertificateGenerator {
    private val keyPair: KeyPair
    private val random = SecureRandom()

    init {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048, random)
        keyPair = keyPairGenerator.generateKeyPair()
    }

    fun generateSelfSignedCertificate(
        subject: String = "CN=Test Certificate",
        validFrom: Date = Date(),
        validTo: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
    ): X509Certificate {
        val issuer = X500Name(subject)
        val serial = BigInteger.valueOf(random.nextLong())
        
        val certBuilder = X509v3CertificateBuilder(
            issuer,
            serial,
            validFrom,
            validTo,
            issuer,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )

        // Add basic constraints
        val basicConstraints = BasicConstraints(true)
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)

        // Add key usage
        val keyUsage = KeyUsage(
            KeyUsage.digitalSignature or
            KeyUsage.keyEncipherment or
            KeyUsage.keyCertSign or
            KeyUsage.cRLSign
        )
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage)

        // Add subject alternative names
        val generalNames = mutableListOf<GeneralName>().apply {
            add(GeneralName(GeneralName.dNSName, "example.com"))
            add(GeneralName(GeneralName.dNSName, "alt.example.com"))
            add(GeneralName(GeneralName.dNSName, "test.example.com"))
            add(GeneralName(GeneralName.iPAddress, "192.168.1.1"))
        }
        certBuilder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(generalNames.toTypedArray()))

        // Sign the certificate
        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA")
            .build(keyPair.private)
        val certHolder: X509CertificateHolder = certBuilder.build(signer)

        // Convert to X509Certificate
        return JcaX509CertificateConverter()
            .getCertificate(certHolder)
    }

    fun generateCACertificate(
        subject: String = "CN=Test CA, O=Test Organization, C=US",
        validFrom: Date = Date(),
        validTo: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
    ): X509Certificate {
        val issuer = X500Name(subject)
        val serial = BigInteger.valueOf(random.nextLong())
        val certBuilder = X509v3CertificateBuilder(
            issuer,
            serial,
            validFrom,
            validTo,
            issuer,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val basicConstraints = BasicConstraints(true)
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)
        val keyUsage = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage)
        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder: X509CertificateHolder = certBuilder.build(signer)
        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    fun generateLeafCertificate(
        subject: String = "CN=Test Certificate",
        issuerCert: X509Certificate,
        issuerKey: PrivateKey,
        subjectKeyPair: KeyPair = keyPair,
        validFrom: Date = Date(),
        validTo: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
        dnsNames: Array<String>? = null,
        ipAddresses: Array<String>? = null
    ): X509Certificate {
        val subjectName = X500Name(subject)
        val issuerName = X500Name(issuerCert.subjectX500Principal.name)
        val serial = BigInteger.valueOf(random.nextLong())
        val certBuilder = X509v3CertificateBuilder(
            issuerName,
            serial,
            validFrom,
            validTo,
            subjectName,
            SubjectPublicKeyInfo.getInstance(subjectKeyPair.public.encoded)
        )
        val basicConstraints = BasicConstraints(false)
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)
        val keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage)
        if (dnsNames != null || ipAddresses != null) {
            val generalNames = mutableListOf<GeneralName>()
            dnsNames?.forEach { dns -> generalNames.add(GeneralName(GeneralName.dNSName, dns)) }
            ipAddresses?.forEach { ip ->
                try {
                    val normalizedIp = InetAddress.getByName(ip).hostAddress
                    generalNames.add(GeneralName(GeneralName.iPAddress, normalizedIp))
                } catch (e: UnknownHostException) {
                    throw IllegalArgumentException("Invalid IP address format: $ip", e)
                }
            }
            if (generalNames.isNotEmpty()) {
                certBuilder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    GeneralNames(generalNames.toTypedArray())
                )
            }
        }
        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)
        val certHolder: X509CertificateHolder = certBuilder.build(signer)
        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    fun generateCertificateChain(
        length: Int = 2,
        subjectPrefix: String = "CN=Test Certificate"
    ): List<X509Certificate> {
        val caCert = generateCACertificate()
        val chain = mutableListOf<X509Certificate>()
        var issuerCert = caCert
        var issuerKey = keyPair.private
        for (i in 0 until length) {
            val subject = "$subjectPrefix $i"
            val subjectKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val cert = generateLeafCertificate(
                subject = subject,
                issuerCert = issuerCert,
                issuerKey = issuerKey,
                subjectKeyPair = subjectKeyPair
            )
            chain.add(cert)
            // For a real chain, next cert would be signed by previous, but for test, keep using CA
        }
        chain.add(issuerCert) // Add CA at the end
        return chain
    }

    fun saveCertificateToFile(certificate: X509Certificate, file: File) {
        file.outputStream().use { out ->
            out.write(certificate.encoded)
        }
    }

    fun saveCertificateChainToFiles(certificates: List<X509Certificate>, directory: File) {
        directory.mkdirs()
        certificates.forEachIndexed { index, cert ->
            val file = File(directory, "cert$index.cer")
            saveCertificateToFile(cert, file)
        }
    }

    companion object {
        fun generateCertificate(
            subject: String,
            issuer: String,
            subjectKeyPair: KeyPair,
            issuerKeyPair: KeyPair,
            dnsNames: Array<String>? = null,
            ipAddresses: Array<String>? = null
        ): X509Certificate {
            val random = SecureRandom()
            val subjectName = X500Name(subject)
            val issuerName = X500Name(issuer)
            val serial = BigInteger.valueOf(random.nextLong())
            
            val certBuilder = X509v3CertificateBuilder(
                issuerName,
                serial,
                Date(),
                Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                subjectName,
                SubjectPublicKeyInfo.getInstance(subjectKeyPair.public.encoded)
            )

            // Add basic constraints
            val basicConstraints = BasicConstraints(false)
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)

            // Add key usage
            val keyUsage = KeyUsage(
                KeyUsage.digitalSignature or
                KeyUsage.keyEncipherment or
                KeyUsage.keyCertSign or
                KeyUsage.cRLSign
            )
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage)

            // Add subject alternative names if provided
            if (dnsNames != null || ipAddresses != null) {
                val generalNames = mutableListOf<GeneralName>()
                
                dnsNames?.forEach { dns ->
                    generalNames.add(GeneralName(GeneralName.dNSName, dns))
                }
                
                ipAddresses?.forEach { ip ->
                    generalNames.add(GeneralName(GeneralName.iPAddress, ip))
                }
                
                if (generalNames.isNotEmpty()) {
                    certBuilder.addExtension(
                        Extension.subjectAlternativeName,
                        false,
                        GeneralNames(generalNames.toTypedArray())
                    )
                }
            }

            // Sign the certificate
            val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA")
                .build(issuerKeyPair.private)
            val certHolder: X509CertificateHolder = certBuilder.build(signer)

            // Convert to X509Certificate
            return JcaX509CertificateConverter()
                .getCertificate(certHolder)
        }
    }
} 