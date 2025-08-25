package org.example.model

import org.example.exception.SSLTestException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * SSLTestResult测试。
 */
class SSLTestResultTest {
    @Test
    fun `test Success result properties`() {
        val connection = createMockSSLConnection()
        val testDuration = Duration.ofMillis(1500)
        val timestamp = Instant.now()

        val result =
            SSLTestResult.Success(
                connection = connection,
                testDuration = testDuration,
                timestamp = timestamp,
            )

        assertAll(
            { assertTrue(result.isSuccess()) },
            { assertFalse(result.isFailure()) },
            { assertFalse(result.isTimeout()) },
            { assertEquals(connection, result.getConnectionOrNull()) },
            { assertNull(result.getErrorOrNull()) },
            { assertEquals("example.com", result.getHostValue()) },
            { assertEquals(443, result.getPortValue()) },
            { assertEquals(testDuration, result.getTestDurationValue()) },
            { assertEquals(timestamp, result.getTimestampValue()) },
        )
    }

    @Test
    fun `test Failure result properties`() {
        val error =
            SSLTestException.ConnectionError(
                host = "test.com",
                port = 8443,
                message = "Connection failed",
            )
        val testDuration = Duration.ofMillis(2000)
        val timestamp = Instant.now()

        val result =
            SSLTestResult.Failure(
                error = error,
                host = "test.com",
                port = 8443,
                testDuration = testDuration,
                timestamp = timestamp,
            )

        assertAll(
            { assertFalse(result.isSuccess()) },
            { assertTrue(result.isFailure()) },
            { assertFalse(result.isTimeout()) },
            { assertNull(result.getConnectionOrNull()) },
            { assertEquals(error, result.getErrorOrNull()) },
            { assertEquals("test.com", result.getHostValue()) },
            { assertEquals(8443, result.getPortValue()) },
            { assertEquals(testDuration, result.getTestDurationValue()) },
            { assertEquals(timestamp, result.getTimestampValue()) },
        )
    }

    @Test
    fun `test Timeout result properties`() {
        val testDuration = Duration.ofMillis(5000)
        val timestamp = Instant.now()

        val result =
            SSLTestResult.Timeout(
                host = "slow.com",
                port = 9443,
                timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                timeoutValue = 3000L,
                testDuration = testDuration,
                timestamp = timestamp,
            )

        assertAll(
            { assertFalse(result.isSuccess()) },
            { assertFalse(result.isFailure()) },
            { assertTrue(result.isTimeout()) },
            { assertNull(result.getConnectionOrNull()) },
            { assertNull(result.getErrorOrNull()) },
            { assertEquals("slow.com", result.getHostValue()) },
            { assertEquals(9443, result.getPortValue()) },
            { assertEquals(testDuration, result.getTestDurationValue()) },
            { assertEquals(timestamp, result.getTimestampValue()) },
        )
    }

    @Test
    fun `test result type checking methods`() {
        val successResult = createSuccessResult()
        val failureResult = createFailureResult()
        val timeoutResult = createTimeoutResult()

        assertAll(
            { assertTrue(successResult.isSuccess()) },
            { assertFalse(successResult.isFailure()) },
            { assertFalse(successResult.isTimeout()) },
            { assertFalse(failureResult.isSuccess()) },
            { assertTrue(failureResult.isFailure()) },
            { assertFalse(failureResult.isTimeout()) },
            { assertFalse(timeoutResult.isSuccess()) },
            { assertFalse(timeoutResult.isFailure()) },
            { assertTrue(timeoutResult.isTimeout()) },
        )
    }

    @Test
    fun `test getConnectionOrNull method`() {
        val successResult = createSuccessResult()
        val failureResult = createFailureResult()
        val timeoutResult = createTimeoutResult()

        assertAll(
            { assertNotNull(successResult.getConnectionOrNull()) },
            { assertNull(failureResult.getConnectionOrNull()) },
            { assertNull(timeoutResult.getConnectionOrNull()) },
        )
    }

    @Test
    fun `test getErrorOrNull method`() {
        val successResult = createSuccessResult()
        val failureResult = createFailureResult()
        val timeoutResult = createTimeoutResult()

        assertAll(
            { assertNull(successResult.getErrorOrNull()) },
            { assertNotNull(failureResult.getErrorOrNull()) },
            { assertNull(timeoutResult.getErrorOrNull()) },
        )
    }

    @Test
    fun `test getHost method for all result types`() {
        val successResult = createSuccessResult()
        val failureResult = createFailureResult()
        val timeoutResult = createTimeoutResult()

        assertAll(
            { assertEquals("example.com", successResult.getHostValue()) },
            { assertEquals("test.com", failureResult.getHostValue()) },
            { assertEquals("slow.com", timeoutResult.getHostValue()) },
        )
    }

    @Test
    fun `test getPort method for all result types`() {
        val successResult = createSuccessResult()
        val failureResult = createFailureResult()
        val timeoutResult = createTimeoutResult()

        assertAll(
            { assertEquals(443, successResult.getPortValue()) },
            { assertEquals(8443, failureResult.getPortValue()) },
            { assertEquals(9443, timeoutResult.getPortValue()) },
        )
    }

    @Test
    fun `test getTestDuration method for all result types`() {
        val testDuration = Duration.ofMillis(1500)

        val successResult =
            SSLTestResult.Success(
                connection = createMockSSLConnection(),
                testDuration = testDuration,
            )
        val failureResult =
            SSLTestResult.Failure(
                error = createMockError(),
                host = "test.com",
                port = 8443,
                testDuration = testDuration,
            )
        val timeoutResult =
            SSLTestResult.Timeout(
                host = "slow.com",
                port = 9443,
                timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                timeoutValue = 3000L,
                testDuration = testDuration,
            )

        assertAll(
            { assertEquals(testDuration, successResult.getTestDurationValue()) },
            { assertEquals(testDuration, failureResult.getTestDurationValue()) },
            { assertEquals(testDuration, timeoutResult.getTestDurationValue()) },
        )
    }

    @Test
    fun `test getTimestamp method for all result types`() {
        val timestamp = Instant.now()

        val successResult =
            SSLTestResult.Success(
                connection = createMockSSLConnection(),
                testDuration = Duration.ofMillis(1500),
                timestamp = timestamp,
            )
        val failureResult =
            SSLTestResult.Failure(
                error = createMockError(),
                host = "test.com",
                port = 8443,
                testDuration = Duration.ofMillis(2000),
                timestamp = timestamp,
            )
        val timeoutResult =
            SSLTestResult.Timeout(
                host = "slow.com",
                port = 9443,
                timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                timeoutValue = 3000L,
                testDuration = Duration.ofMillis(5000),
                timestamp = timestamp,
            )

        assertAll(
            { assertEquals(timestamp, successResult.getTimestampValue()) },
            { assertEquals(timestamp, failureResult.getTimestampValue()) },
            { assertEquals(timestamp, timeoutResult.getTimestampValue()) },
        )
    }

    private fun createMockSSLConnection(): SSLConnection {
        return SSLConnection(
            host = "example.com",
            port = 443,
            protocol = "TLSv1.3",
            cipherSuite = "TLS_AES_256_GCM_SHA384",
            handshakeTime = Duration.ofMillis(1500),
            isSecure = true,
            certificateChain = emptyList(),
            certificateValidation = null,
        )
    }

    private fun createMockError(): SSLTestException {
        return SSLTestException.ConnectionError(
            host = "test.com",
            port = 8443,
            message = "Connection failed",
        )
    }

    private fun createSuccessResult(): SSLTestResult.Success {
        return SSLTestResult.Success(
            connection = createMockSSLConnection(),
            testDuration = Duration.ofMillis(1500),
        )
    }

    private fun createFailureResult(): SSLTestResult.Failure {
        return SSLTestResult.Failure(
            error = createMockError(),
            host = "test.com",
            port = 8443,
            testDuration = Duration.ofMillis(2000),
        )
    }

    private fun createTimeoutResult(): SSLTestResult.Timeout {
        return SSLTestResult.Timeout(
            host = "slow.com",
            port = 9443,
            timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
            timeoutValue = 3000L,
            testDuration = Duration.ofMillis(5000),
        )
    }
}
