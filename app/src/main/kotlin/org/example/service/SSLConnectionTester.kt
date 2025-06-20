package org.example.service

import org.example.model.SSLConnection
import org.example.model.SSLTestConfig

sealed interface SSLConnectionTester {
    suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection>
}
