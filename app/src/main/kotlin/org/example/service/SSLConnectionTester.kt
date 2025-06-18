package org.example.service

import org.example.SSLTestConfig
import org.example.exception.SSLTestException
import org.example.model.SSLConnection

sealed interface SSLConnectionTester {
    suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection>
}
