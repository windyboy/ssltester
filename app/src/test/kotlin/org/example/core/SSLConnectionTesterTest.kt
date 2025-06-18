package org.example.core

import kotlinx.coroutines.runBlocking
import org.example.model.SSLConnection
import org.example.service.SSLConnectionTesterImpl
import org.example.SSLTestConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SSLConnectionTesterTest {
    private val tester = SSLConnectionTesterImpl()

    @Test
    fun `test successful connection to valid host`() = runBlocking {
        val connection = tester.testConnection(
            "github.com",
            443,
            SSLTestConfig(connectionTimeout = 5000)
        )

        assertTrue(connection.isSecure)
        assertEquals("github.com", connection.host)
        assertEquals(443, connection.port)
        assertTrue(connection.protocol.startsWith("TLS"))
        assertTrue(connection.cipherSuite.isNotEmpty())
        assertTrue(connection.certificateChain.isNotEmpty())
    }

    @Test
    fun `test connection to invalid host`() = runBlocking {
        val connection = tester.testConnection(
            "invalid-host-that-does-not-exist.com",
            443,
            SSLTestConfig(connectionTimeout = 1000)
        )

        assertFalse(connection.isSecure)
        assertTrue(connection.protocol.contains("Unknown"))
        assertTrue(connection.certificateChain.isEmpty())
    }

    @Test
    fun `test connection timeout`() = runBlocking {
        val connection = tester.testConnection(
            "github.com",
            443,
            SSLTestConfig(connectionTimeout = 1)
        )

        assertFalse(connection.isSecure)
        assertTrue(connection.protocol.contains("timeout") || connection.protocol.contains("Unknown"))
    }

    @Test
    fun `test connection to invalid port`() = runBlocking {
        val connection = tester.testConnection(
            "github.com",
            1,
            SSLTestConfig(connectionTimeout = 1000)
        )

        assertFalse(connection.isSecure)
        assertTrue(connection.protocol.contains("Connection failed") || connection.protocol.contains("Unknown"))
    }
} 