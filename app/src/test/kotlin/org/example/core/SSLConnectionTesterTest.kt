package org.example.core

import kotlinx.coroutines.runBlocking
import org.example.SSLConnectionTesterImpl
import org.example.exception.SSLTestException
import org.example.model.SSLTestConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SSLConnectionTesterTest {
    private val tester = SSLConnectionTesterImpl()

    @Test
    fun `test connection to invalid host`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-does-not-exist.com",
                    443,
                    SSLTestConfig(
                        connectionTimeout = 1000,
                    ),
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
    fun `test connection timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(
                        connectionTimeout = 1,
                    ),
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
    fun `test connection to invalid port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    44443,
                    SSLTestConfig(
                        connectionTimeout = 5000,
                    ),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
            assertTrue(
                error.message?.contains("Connection failed") == true ||
                    error.message?.contains("Unknown") == true ||
                    error.message?.contains("Connection refused") == true ||
                    error.message?.contains("timed out") == true,
                "Unexpected error message: ${error.message}",
            )
        }
    }

    @Test
    fun `test SSL configuration validation`() {
        val config =
            SSLTestConfig(
                connectionTimeout = 5000,
            )
        assertEquals(5000, config.connectionTimeout)
    }
}
