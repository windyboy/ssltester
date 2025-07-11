package org.example.formatter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import org.example.CertificateValidator
import org.example.model.SSLConnection

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
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root)
    }

    override fun getFileExtension(): String = "json"
}
