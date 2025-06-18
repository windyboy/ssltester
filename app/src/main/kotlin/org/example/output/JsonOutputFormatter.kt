package org.example.output

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import org.example.model.SSLConnection
import java.time.format.DateTimeFormatter

class JsonOutputFormatter : OutputFormatter {
    private val objectMapper =
        ObjectMapper().apply {
            registerModule(JavaTimeModule())
            enable(SerializationFeature.INDENT_OUTPUT)
            disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        }

    override fun format(connection: SSLConnection): String {
        val result =
            mapOf(
                "host" to connection.host,
                "port" to connection.port,
                "protocol" to connection.protocol,
                "cipherSuite" to connection.cipherSuite,
                "handshakeTimeMs" to connection.handshakeTime.toMillis(),
                "isSecure" to connection.isSecure,
                "certificates" to
                    connection.certificateChain.map { cert ->
                        mapOf(
                            "subject" to cert.subjectX500Principal.toString(),
                            "issuer" to cert.issuerX500Principal.toString(),
                            "validFrom" to formatDate(cert.notBefore.toInstant()),
                            "validUntil" to formatDate(cert.notAfter.toInstant()),
                            "serialNumber" to cert.serialNumber.toString(16).uppercase(),
                        )
                    },
            )
        return objectMapper.writeValueAsString(result)
    }

    private fun formatDate(date: java.time.Instant): String {
        return DateTimeFormatter.ISO_INSTANT.format(date)
    }

    override fun getFileExtension(): String = "json"
}
