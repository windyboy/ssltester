package org.example.core

import kotlinx.coroutines.runBlocking
import org.example.exception.SSLTestException
import org.example.model.SSLTestConfig
import org.example.service.SSLConnectionTesterImpl
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SSLConnectionTesterTest {
    private val tester = SSLConnectionTesterImpl()

    @Test
    fun `test successful connection to valid host`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "github.com",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isSuccess)
            val connection = result.getOrThrow()
            assertTrue(connection.isSecure)
            assertEquals("github.com", connection.host)
            assertEquals(443, connection.port)
            assertTrue(connection.protocol.startsWith("TLS"))
            assertTrue(connection.cipherSuite.isNotEmpty())
            assertTrue(connection.certificateChain.isNotEmpty())
        }
    }

    @Test
    fun `test connection to invalid host`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-does-not-exist.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
            assertTrue(error.message.contains("Connection failed") || error.message.contains("Unknown"))
        }
    }

    @Test
    fun `test connection timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "github.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
            assertTrue(error?.message?.contains("timeout") == true || error?.message?.contains("Unknown") == true)
        }
    }

    @Test
    fun `test connection to invalid port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    44443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
            assertTrue(
                error.message.contains("Connection failed") ||
                    error.message.contains("Unknown") ||
                    error.message.contains("Connection refused") ||
                    error.message.contains("timed out"),
                "Unexpected error message: ${error?.message}",
            )
        }
    }
}
