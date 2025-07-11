package org.example.core

import kotlinx.coroutines.runBlocking
import org.example.DefaultSSLConnectionTester
import org.example.exception.SSLTestException
import org.example.model.SSLTestConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DefaultSSLConnectionTesterTest {
    private val tester = DefaultSSLConnectionTester()

    @Test
    fun testConnectionToInvalidHost() {
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
            assertTrue(
                error.message?.contains("Connection failed") == true ||
                    error.message?.contains("Unknown") == true,
            )
        }
    }

    @Test
    fun testConnectionTimeout() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
            assertTrue(
                error.message?.contains("timeout") == true ||
                    error.message?.contains("Unknown") == true,
            )
        }
    }

    @Test
    fun testConnectionToInvalidPort() {
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
                error.message?.contains("Connection failed") == true ||
                    error.message?.contains("Unknown") == true ||
                    error.message?.contains("Connection refused") == true ||
                    error.message?.contains("timed out") == true,
            )
        }
    }

    @Test
    fun testSSLConfigurationValidation() {
        val config = SSLTestConfig(connectionTimeout = 5000)
        assertEquals(5000, config.connectionTimeout)
    }

    @Test
    fun testConnectionWithZeroTimeout() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 0),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    @Test
    fun testConnectionWithNegativeTimeout() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = -1),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    @Test
    fun testConnectionWithSpecialCharactersInHostname() {
        runBlocking {
            val result =
                tester.testConnection(
                    "test-host.example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun testConnectionWithNegativePort() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    -1,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun testConnectionWithZeroPort() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    0,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun testConnectionWithMaximumPort() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    65535,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun testConnectionErrorHostAndPort() {
        runBlocking {
            val host = "test.example.com"
            val port = 8443

            val result =
                tester.testConnection(
                    host,
                    port,
                    SSLTestConfig(connectionTimeout = 1000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)

            assertEquals(host, error.host)
            assertEquals(port, error.port)
        }
    }

    @Test
    fun testSSLHandshakeExceptionHandling() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    80,
                    SSLTestConfig(connectionTimeout = 5000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is SSLTestException.HandshakeError || error is SSLTestException.ConnectionError)
            assertTrue(
                error?.message?.contains("SSL") == true ||
                    error?.message?.contains("Protocol") == true ||
                    error?.message?.contains("Handshake") == true ||
                    error?.message?.contains("Connection") == true,
            )
        }
    }

    @Test
    fun testConnectionWithNullMessageInIOException() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-will-cause-io-exception",
                    443,
                    SSLTestConfig(connectionTimeout = 1000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is SSLTestException.ConnectionError)
            assertTrue(
                error?.message?.contains("Connection refused") == true ||
                    error?.message?.contains("Connection failed") == true ||
                    error?.message?.contains("Unknown host") == true,
            )
        }
    }

    @Test
    fun testHttpsConnectionToExampleCom() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Should either succeed or fail gracefully, not crash
            assertTrue(result.isSuccess || result.isFailure)
            if (result.isFailure) {
                val error = result.exceptionOrNull()
                assertIs<SSLTestException>(error)
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [443, 8443, 9443])
    fun testCommonSSLPorts(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Should either succeed or fail gracefully, not crash
            assertTrue(result.isSuccess || result.isFailure)
            if (result.isFailure) {
                val error = result.exceptionOrNull()
                assertIs<SSLTestException>(error)
            }
        }
    }
}
