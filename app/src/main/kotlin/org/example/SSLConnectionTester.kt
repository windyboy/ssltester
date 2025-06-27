package org.example

import org.example.model.SSLConnection
import org.example.model.SSLTestConfig

/**
 * SSL 连接测试器接口。
 * 定义 SSL/TLS 连接测试的核心功能。
 */
interface SSLConnectionTester {
    /**
     * 测试指定主机和端口的 SSL/TLS 连接。
     * @param host 目标主机
     * @param port 目标端口
     * @param config 测试配置
     * @return 测试结果，成功返回 SSLConnection，失败返回异常
     */
    suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection>
}
