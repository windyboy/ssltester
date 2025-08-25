package org.example.retry

import kotlinx.coroutines.delay
import org.example.exception.SSLTestException
import org.example.logging.SSLTestContext
import org.example.logging.StructuredLogger
import org.example.model.SSLTestResult
import java.time.Duration
import java.time.Instant

/**
 * 重试管理器。
 * 提供智能重试逻辑，包括指数退避和错误分类。
 */
class RetryManager(
    private val logger: StructuredLogger = StructuredLogger.create(),
) {
    /**
     * 重试策略。
     */
    sealed class RetryStrategy {
        /** 不重试 */
        object NoRetry : RetryStrategy()

        /** 固定延迟重试 */
        data class FixedDelay(val delayMs: Long) : RetryStrategy()

        /** 指数退避重试 */
        data class ExponentialBackoff(
            val initialDelayMs: Long,
            val maxDelayMs: Long,
            val multiplier: Double = 2.0,
        ) : RetryStrategy()
    }

    /**
     * 重试结果。
     */
    sealed class RetryResult {
        /** 重试成功 */
        data class Success(
            val result: SSLTestResult.Success,
            val attemptCount: Int,
            val totalDuration: Duration,
        ) : RetryResult()

        /** 重试失败 */
        data class Failure(
            val lastError: SSLTestException,
            val attemptCount: Int,
            val totalDuration: Duration,
            val allErrors: List<SSLTestException>,
        ) : RetryResult()

        /** 重试超时 */
        data class Timeout(
            val timeoutType: SSLTestException.TimeoutType,
            val attemptCount: Int,
            val totalDuration: Duration,
        ) : RetryResult()
    }

    /**
     * 执行带重试的SSL测试。
     */
    suspend fun executeWithRetry(
        context: SSLTestContext,
        operation: suspend () -> SSLTestResult,
        strategy: RetryStrategy = RetryStrategy.ExponentialBackoff(1000, 10000),
    ): RetryResult {
        if (strategy is RetryStrategy.NoRetry) {
            return executeSingleAttempt(context, operation)
        }

        val startTime = Instant.now()
        var attemptCount = 0
        val allErrors = mutableListOf<SSLTestException>()

        while (attemptCount < context.maxRetries) {
            attemptCount++

            try {
                logger.logRetryAttempt(context, attemptCount, context.maxRetries, "Starting attempt")

                val result = operation()

                when (result) {
                    is SSLTestResult.Success -> {
                        logger.logRetrySuccess(context, attemptCount)
                        return RetryResult.Success(
                            result = result,
                            attemptCount = attemptCount,
                            totalDuration = Duration.between(startTime, Instant.now()),
                        )
                    }
                    is SSLTestResult.Failure -> {
                        allErrors.add(result.error)

                        if (shouldRetry(result.error)) {
                            if (attemptCount < context.maxRetries) {
                                val delayMs = calculateDelay(strategy, attemptCount)
                                logger.logRetryAttempt(
                                    context,
                                    attemptCount,
                                    context.maxRetries,
                                    "Retrying after ${delayMs}ms due to: ${result.error.javaClass.simpleName}",
                                )
                                delay(delayMs)
                                continue
                            }
                        }

                        // 不应该重试或已达到最大重试次数
                        logger.logRetryFailure(context, attemptCount, context.maxRetries)
                        return RetryResult.Failure(
                            lastError = result.error,
                            attemptCount = attemptCount,
                            totalDuration = Duration.between(startTime, Instant.now()),
                            allErrors = allErrors,
                        )
                    }
                    is SSLTestResult.Timeout -> {
                        // 超时通常应该重试
                        if (attemptCount < context.maxRetries) {
                            val delayMs = calculateDelay(strategy, attemptCount)
                            logger.logRetryAttempt(
                                context,
                                attemptCount,
                                context.maxRetries,
                                "Retrying after ${delayMs}ms due to timeout: ${result.timeoutType}",
                            )
                            delay(delayMs)
                            continue
                        }

                        return RetryResult.Timeout(
                            timeoutType = result.timeoutType,
                            attemptCount = attemptCount,
                            totalDuration = Duration.between(startTime, Instant.now()),
                        )
                    }
                }
            } catch (e: Exception) {
                val sslException =
                    when (e) {
                        is SSLTestException -> e
                        else ->
                            SSLTestException.ConfigurationError(
                                message = "Unexpected error during retry: ${e.message}",
                                cause = e,
                            )
                    }

                allErrors.add(sslException)

                if (shouldRetry(sslException) && attemptCount < context.maxRetries) {
                    val delayMs = calculateDelay(strategy, attemptCount)
                    logger.logRetryAttempt(
                        context,
                        attemptCount,
                        context.maxRetries,
                        "Retrying after ${delayMs}ms due to: ${sslException.javaClass.simpleName}",
                    )
                    delay(delayMs)
                    continue
                }

                return RetryResult.Failure(
                    lastError = sslException,
                    attemptCount = attemptCount,
                    totalDuration = Duration.between(startTime, Instant.now()),
                    allErrors = allErrors,
                )
            }
        }

        // 达到最大重试次数
        val lastError =
            allErrors.lastOrNull() ?: SSLTestException.ConfigurationError(
                message = "Maximum retry attempts reached",
            )

        return RetryResult.Failure(
            lastError = lastError,
            attemptCount = attemptCount,
            totalDuration = Duration.between(startTime, Instant.now()),
            allErrors = allErrors,
        )
    }

    /**
     * 执行单次尝试。
     */
    private suspend fun executeSingleAttempt(
        context: SSLTestContext,
        operation: suspend () -> SSLTestResult,
    ): RetryResult {
        val startTime = Instant.now()

        return try {
            val result = operation()
            when (result) {
                is SSLTestResult.Success ->
                    RetryResult.Success(
                        result = result,
                        attemptCount = 1,
                        totalDuration = Duration.between(startTime, Instant.now()),
                    )
                is SSLTestResult.Failure ->
                    RetryResult.Failure(
                        lastError = result.error,
                        attemptCount = 1,
                        totalDuration = Duration.between(startTime, Instant.now()),
                        allErrors = listOf(result.error),
                    )
                is SSLTestResult.Timeout ->
                    RetryResult.Timeout(
                        timeoutType = result.timeoutType,
                        attemptCount = 1,
                        totalDuration = Duration.between(startTime, Instant.now()),
                    )
            }
        } catch (e: Exception) {
            val sslException =
                when (e) {
                    is SSLTestException -> e
                    else ->
                        SSLTestException.ConfigurationError(
                            message = "Unexpected error: ${e.message}",
                            cause = e,
                        )
                }

            RetryResult.Failure(
                lastError = sslException,
                attemptCount = 1,
                totalDuration = Duration.between(startTime, Instant.now()),
                allErrors = listOf(sslException),
            )
        }
    }

    /**
     * 判断是否应该重试。
     */
    private fun shouldRetry(error: SSLTestException): Boolean =
        when (error) {
            is SSLTestException.ConfigurationError -> false // 配置错误不应该重试
            is SSLTestException.TimeoutError -> true // 超时应该重试
            is SSLTestException.ConnectionError -> true // 连接错误应该重试
            is SSLTestException.HandshakeError -> {
                // 握手错误根据具体原因决定是否重试
                when (error.cause) {
                    is java.net.SocketTimeoutException -> true
                    is javax.net.ssl.SSLProtocolException -> false // 协议错误不应该重试
                    else -> true
                }
            }
            is SSLTestException.CertificateError -> false // 证书错误不应该重试
        }

    /**
     * 计算延迟时间。
     */
    private fun calculateDelay(
        strategy: RetryStrategy,
        attempt: Int,
    ): Long =
        when (strategy) {
            is RetryStrategy.FixedDelay -> strategy.delayMs
            is RetryStrategy.ExponentialBackoff -> {
                val delay = (strategy.initialDelayMs * Math.pow(strategy.multiplier, (attempt - 1).toDouble())).toLong()
                minOf(delay, strategy.maxDelayMs)
            }
            is RetryStrategy.NoRetry -> 0L
        }

    companion object {
        /**
         * 创建默认的重试管理器。
         */
        fun create(): RetryManager = RetryManager()
    }
}
