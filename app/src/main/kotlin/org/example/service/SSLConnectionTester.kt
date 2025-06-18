package org.example.service

import org.example.model.SSLConnection
import org.example.SSLTestConfig

interface SSLConnectionTester {
    suspend fun testConnection(host: String, port: Int, config: SSLTestConfig): SSLConnection
} 