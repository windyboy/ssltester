package org.example.formatter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import org.example.CertificateValidator
import org.example.model.SSLConnection
import java.security.cert.X509Certificate

class JsonOutputFormatter : OutputFormatter {
    private val mapper = ObjectMapper()

    override fun format(connection: SSLConnection): String {
        val root: ObjectNode = JsonNodeFactory.instance.objectNode()
        root.put("host", connection.host)
        root.put("port", connection.port)
        root.put("protocol", connection.protocol)
        root.put("cipherSuite", connection.cipherSuite)
        connection.certificateValidation?.let { validation ->
            val certNode: ObjectNode = JsonNodeFactory.instance.objectNode()
            val revocationStatusString =
                when (val status = validation.revocationStatus) {
                    is CertificateValidator.RevocationStatus.Valid -> "Valid"
                    is CertificateValidator.RevocationStatus.Revoked -> "Revoked: ${status.reason}"
                    is CertificateValidator.RevocationStatus.Unknown -> "Unknown"
                    is CertificateValidator.RevocationStatus.Error -> "Error: ${status.message}"
                }
            certNode.put("isValid", validation.isValid)
            certNode.put("revocationStatus", revocationStatusString)
            val errorsArray: ArrayNode = JsonNodeFactory.instance.arrayNode()
            validation.errors.forEach { errorsArray.add(it) }
            certNode.set<ArrayNode>("errors", errorsArray)
            root.set<ObjectNode>("certificateValidation", certNode)
        }

        // Add certificate chain information
        if (connection.certificateChain.isNotEmpty()) {
            val chainArray: ArrayNode = JsonNodeFactory.instance.arrayNode()
            connection.certificateChain.forEachIndexed { index, cert ->
                val certNode: ObjectNode = JsonNodeFactory.instance.objectNode()
                certNode.put("index", index + 1)
                certNode.put("subject", cert.subjectX500Principal.toString())
                certNode.put("issuer", cert.issuerX500Principal.toString())
                certNode.put("serialNumber", cert.serialNumber.toString())
                certNode.put("validFrom", cert.notBefore.toString())
                certNode.put("validUntil", cert.notAfter.toString())
                certNode.put("signatureAlgorithm", cert.sigAlgName)
                certNode.put("publicKeyAlgorithm", cert.publicKey.algorithm)
                certNode.put("keySize", cert.publicKey.encoded.size * 8)

                // Add DNS names if available
                val dnsNames = extractDNSNames(cert)
                if (dnsNames.isNotEmpty()) {
                    val dnsArray: ArrayNode = JsonNodeFactory.instance.arrayNode()
                    dnsNames.forEach { dnsArray.add(it) }
                    certNode.set<ArrayNode>("dnsNames", dnsArray)
                }

                // Add IP addresses if available
                val ipAddresses = extractIPAddresses(cert)
                if (ipAddresses.isNotEmpty()) {
                    val ipArray: ArrayNode = JsonNodeFactory.instance.arrayNode()
                    ipAddresses.forEach { ipArray.add(it) }
                    certNode.set<ArrayNode>("ipAddresses", ipArray)
                }

                chainArray.add(certNode)
            }
            root.set<ArrayNode>("certificateChain", chainArray)
        }

        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root)
    }

    override fun getFileExtension(): String = "json"

    private fun extractDNSNames(cert: X509Certificate): List<String> {
        return try {
            val sans = cert.getSubjectAlternativeNames()
            sans?.mapNotNull { san ->
                val type = san[0] as? Int
                val value = san[1] as? String
                if (type == 2) value else null // Type 2 is DNS name
            } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun extractIPAddresses(cert: X509Certificate): List<String> {
        return try {
            val sans = cert.getSubjectAlternativeNames()
            sans?.mapNotNull { san ->
                val type = san[0] as? Int
                val value = san[1] as? String
                if (type == 7) value else null // Type 7 is IP address
            } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
