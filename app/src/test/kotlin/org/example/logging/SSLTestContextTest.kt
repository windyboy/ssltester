package org.example.logging

import org.example.model.OutputFormat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * SSLTestContext测试。
 */
class SSLTestContextTest {
    @Test
    fun `test context creation with all parameters`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.JSON,
                outputFile = "test.json",
                enableHostnameVerification = true,
                enableOCSPValidation = false,
                maxRetries = 3,
                retryDelay = 2000L,
            )

        assertAll(
            { assertEquals("example.com", context.host) },
            { assertEquals(443, context.port) },
            { assertEquals(5000, context.connectionTimeout) },
            { assertEquals(10000, context.readTimeout) },
            { assertEquals(15000, context.handshakeTimeout) },
            { assertEquals(OutputFormat.JSON, context.format) },
            { assertEquals("test.json", context.outputFile) },
            { assertTrue(context.enableHostnameVerification) },
            { assertFalse(context.enableOCSPValidation) },
            { assertEquals(3, context.maxRetries) },
            { assertEquals(2000L, context.retryDelay) },
            { assertNotNull(context.sessionId) },
            { assertTrue(context.sessionId.startsWith("ssl-test-")) },
            { assertNotNull(context.timestamp) },
        )
    }

    @Test
    fun `test context creation with default values`() {
        val context =
            SSLTestContext(
                host = "test.com",
                port = 8443,
                connectionTimeout = 3000,
                readTimeout = 5000,
                handshakeTimeout = 8000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = false,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        assertAll(
            { assertEquals("test.com", context.host) },
            { assertEquals(8443, context.port) },
            { assertEquals(3000, context.connectionTimeout) },
            { assertEquals(5000, context.readTimeout) },
            { assertEquals(8000, context.handshakeTimeout) },
            { assertEquals(OutputFormat.TXT, context.format) },
            { assertEquals(null, context.outputFile) },
            { assertFalse(context.enableHostnameVerification) },
            { assertTrue(context.enableOCSPValidation) },
            { assertEquals(1, context.maxRetries) },
            { assertEquals(1000L, context.retryDelay) },
            { assertNotNull(context.sessionId) },
            { assertNotNull(context.timestamp) },
        )
    }

    @Test
    fun `test getConnectionId method`() {
        val context =
            SSLTestContext(
                host = "api.example.com",
                port = 9443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.YAML,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 2,
                retryDelay = 1500L,
            )

        assertEquals("api.example.com:9443", context.getConnectionId())
    }

    @Test
    fun `test getTimeoutSummary method`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val expected = "connect=5000ms,read=10000ms,handshake=15000ms"
        assertEquals(expected, context.getTimeoutSummary())
    }

    @Test
    fun `test getValidationSummary method`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = false,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val expected = "hostname=true,ocsp=false"
        assertEquals(expected, context.getValidationSummary())
    }

    @Test
    fun `test getRetrySummary method`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 3,
                retryDelay = 2000L,
            )

        val expected = "max=3,delay=2000ms"
        assertEquals(expected, context.getRetrySummary())
    }

    @Test
    fun `test toLogFields method`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.JSON,
                outputFile = "test.json",
                enableHostnameVerification = true,
                enableOCSPValidation = false,
                maxRetries = 2,
                retryDelay = 1500L,
            )

        val logFields = context.toLogFields()

        assertAll(
            { assertEquals(13, logFields.size) },
            { assertEquals("example.com", logFields["host"]) },
            { assertEquals("443", logFields["port"]) },
            { assertEquals("5000", logFields["connectionTimeout"]) },
            { assertEquals("10000", logFields["readTimeout"]) },
            { assertEquals("15000", logFields["handshakeTimeout"]) },
            { assertEquals("JSON", logFields["format"]) },
            { assertEquals("test.json", logFields["outputFile"]) },
            { assertEquals("true", logFields["enableHostnameVerification"]) },
            { assertEquals("false", logFields["enableOCSPValidation"]) },
            { assertEquals("2", logFields["maxRetries"]) },
            { assertEquals("1500", logFields["retryDelay"]) },
            { assertNotNull(logFields["sessionId"]) },
            { assertNotNull(logFields["timestamp"]) },
        )
    }

    @Test
    fun `test toLogFields method with null outputFile`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val logFields = context.toLogFields()
        assertEquals("none", logFields["outputFile"])
    }

    @Test
    fun `test createRetryContext method`() {
        val originalContext =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val retryContext = originalContext.createRetryContext(2)

        assertAll(
            { assertEquals(originalContext.host, retryContext.host) },
            { assertEquals(originalContext.port, retryContext.port) },
            { assertEquals(originalContext.connectionTimeout, retryContext.connectionTimeout) },
            { assertEquals(originalContext.readTimeout, retryContext.readTimeout) },
            { assertEquals(originalContext.handshakeTimeout, retryContext.handshakeTimeout) },
            { assertEquals(originalContext.format, retryContext.format) },
            { assertEquals(originalContext.outputFile, retryContext.outputFile) },
            { assertEquals(originalContext.enableHostnameVerification, retryContext.enableHostnameVerification) },
            { assertEquals(originalContext.enableOCSPValidation, retryContext.enableOCSPValidation) },
            { assertEquals(originalContext.maxRetries, retryContext.maxRetries) },
            { assertEquals(originalContext.retryDelay, retryContext.retryDelay) },
            { assertNotEquals(originalContext.sessionId, retryContext.sessionId) },
            { assertTrue(retryContext.sessionId.endsWith("-retry-2")) },
            { assertEquals(originalContext.timestamp, retryContext.timestamp) },
        )
    }

    @Test
    fun `test sessionId uniqueness`() {
        val context1 =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val context2 =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        assertNotEquals(context1.sessionId, context2.sessionId)
    }

    @Test
    fun `test sessionId format`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val sessionId = context.sessionId
        assertAll(
            { assertTrue(sessionId.startsWith("ssl-test-")) },
            { assertTrue(sessionId.matches(Regex("ssl-test-\\d+-\\d+"))) },
        )
    }

    @Test
    fun `test timestamp is recent`() {
        val context =
            SSLTestContext(
                host = "example.com",
                port = 443,
                connectionTimeout = 5000,
                readTimeout = 10000,
                handshakeTimeout = 15000,
                format = OutputFormat.TXT,
                outputFile = null,
                enableHostnameVerification = true,
                enableOCSPValidation = true,
                maxRetries = 1,
                retryDelay = 1000L,
            )

        val now = Instant.now()
        val timeDifference = kotlin.math.abs(now.toEpochMilli() - context.timestamp.toEpochMilli())

        // 时间差应该在1秒内
        assertTrue(timeDifference < 1000, "Timestamp should be recent, difference: ${timeDifference}ms")
    }
}
