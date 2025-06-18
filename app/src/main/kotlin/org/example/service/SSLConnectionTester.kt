package org.example.service

import org.example.SSLTestConfig
import org.example.model.SSLConnection

interface SSLConnectionTester {
    suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): SSLConnection
}
