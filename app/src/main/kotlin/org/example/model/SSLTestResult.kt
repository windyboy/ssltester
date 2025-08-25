package org.example.model

import org.example.exception.SSLTestException
import java.time.Duration

/**
 * SSL测试结果。
 * 使用密封类确保类型安全，避免空值返回。
 */
sealed class SSLTestResult {
    /**
     * 成功的SSL测试结果。
     */
    data class Success(
        val connection: SSLConnection,
        val testDuration: Duration,
        val timestamp: java.time.Instant = java.time.Instant.now(),
    ) : SSLTestResult()

    /**
     * 失败的SSL测试结果。
     */
    data class Failure(
        val error: SSLTestException,
        val host: String,
        val port: Int,
        val testDuration: Duration,
        val timestamp: java.time.Instant = java.time.Instant.now(),
    ) : SSLTestResult()

    /**
     * 超时的SSL测试结果。
     */
    data class Timeout(
        val host: String,
        val port: Int,
        val timeoutType: org.example.exception.SSLTestException.TimeoutType,
        val timeoutValue: Long,
        val testDuration: Duration,
        val timestamp: java.time.Instant = java.time.Instant.now(),
    ) : SSLTestResult()

    /**
     * 检查是否为成功结果。
     */
    fun isSuccess(): Boolean = this is Success

    /**
     * 检查是否为失败结果。
     */
    fun isFailure(): Boolean = this is Failure

    /**
     * 检查是否为超时结果。
     */
    fun isTimeout(): Boolean = this is Timeout

    /**
     * 获取连接信息（如果成功）。
     */
    fun getConnectionOrNull(): SSLConnection? =
        when (this) {
            is Success -> connection
            else -> null
        }

    /**
     * 获取错误信息（如果失败）。
     */
    fun getErrorOrNull(): SSLTestException? =
        when (this) {
            is Failure -> error
            else -> null
        }

    /**
     * 获取主机名。
     */
    fun getHostValue(): String =
        when (this) {
            is Success -> connection.host
            is Failure -> host
            is Timeout -> host
        }

    /**
     * 获取端口号。
     */
    fun getPortValue(): Int =
        when (this) {
            is Success -> connection.port
            is Failure -> port
            is Timeout -> port
        }

    /**
     * 获取测试持续时间。
     */
    fun getTestDurationValue(): Duration =
        when (this) {
            is Success -> testDuration
            is Failure -> testDuration
            is Timeout -> testDuration
        }

    /**
     * 获取时间戳。
     */
    fun getTimestampValue(): java.time.Instant =
        when (this) {
            is Success -> timestamp
            is Failure -> timestamp
            is Timeout -> timestamp
        }
}
