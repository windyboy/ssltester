package org.example.domain.service

import org.example.domain.model.SSLConnection
import org.example.config.SSLTestConfig

/**
 * Service interface for testing SSL/TLS connections.
 */
interface SSLConnectionTester {
    /**
     * Tests an SSL connection to the specified host and port.
     * @param host The hostname to test
     * @param port The port to test
     * @param config The SSL test configuration
     * @return SSL connection result
     */
    suspend fun testConnection(host: String, port: Int, config: SSLTestConfig): SSLConnection
} 