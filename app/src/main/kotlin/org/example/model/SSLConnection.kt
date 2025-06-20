package org.example.model

import java.security.cert.X509Certificate
import java.time.Duration

/**
 * SSL 连接结果数据。
 * @property host 目标主机
 * @property port 目标端口
 * @property protocol 协议版本
 * @property cipherSuite 密码套件
 * @property handshakeTime 握手耗时
 * @property isSecure 是否安全
 * @property certificateChain 证书链
 */
data class SSLConnection(
    val host: String,
    val port: Int,
    val protocol: String,
    val cipherSuite: String,
    val handshakeTime: Duration,
    val isSecure: Boolean,
    val certificateChain: List<X509Certificate> = emptyList(),
)
