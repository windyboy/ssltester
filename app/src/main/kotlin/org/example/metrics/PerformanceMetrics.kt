package org.example.metrics

import java.time.Duration
import java.time.Instant

/**
 * 性能指标收集器。
 * 跟踪SSL测试的各种时间和性能方面。
 */
class PerformanceMetrics {
    private val startTime = Instant.now()
    private val metrics = mutableMapOf<String, Duration>()
    private val checkpoints = mutableMapOf<String, Instant>()

    /**
     * 添加检查点。
     */
    fun addCheckpoint(name: String) {
        checkpoints[name] = Instant.now()
    }

    /**
     * 记录指标。
     */
    fun recordMetric(
        name: String,
        duration: Duration,
    ) {
        metrics[name] = duration
    }

    /**
     * 计算两个检查点之间的持续时间。
     */
    fun calculateDuration(
        fromCheckpoint: String,
        toCheckpoint: String,
    ): Duration? {
        val from = checkpoints[fromCheckpoint] ?: return null
        val to = checkpoints[toCheckpoint] ?: return null
        return Duration.between(from, to)
    }

    /**
     * 获取总测试时间。
     */
    fun getTotalDuration(): Duration = Duration.between(startTime, Instant.now())

    /**
     * 获取所有指标。
     */
    fun getAllMetrics(): Map<String, Duration> = metrics.toMap()

    /**
     * 获取所有检查点。
     */
    fun getAllCheckpoints(): Map<String, Instant> = checkpoints.toMap()

    /**
     * 生成性能报告。
     */
    fun generateReport(): PerformanceReport {
        val totalDuration = getTotalDuration()
        val avgMetric =
            if (metrics.isNotEmpty()) {
                val totalMillis = metrics.values.sumOf { it.toMillis() }
                Duration.ofMillis(totalMillis / metrics.size)
            } else {
                Duration.ZERO
            }

        return PerformanceReport(
            totalDuration = totalDuration,
            metrics = metrics.toMap(),
            checkpoints = checkpoints.toMap(),
            averageMetricDuration = avgMetric,
            metricCount = metrics.size,
            checkpointCount = checkpoints.size,
        )
    }

    /**
     * 重置指标。
     */
    fun reset() {
        metrics.clear()
        checkpoints.clear()
    }

    companion object {
        /**
         * 预定义的检查点名称。
         */
        object Checkpoints {
            const val TEST_START = "test_start"
            const val CONFIG_VALIDATION = "config_validation"
            const val TCP_CONNECTION = "tcp_connection"
            const val SSL_HANDSHAKE = "ssl_handshake"
            const val CERTIFICATE_VALIDATION = "certificate_validation"
            const val TEST_COMPLETE = "test_complete"
        }

        /**
         * 预定义的指标名称。
         */
        object Metrics {
            const val CONFIG_VALIDATION_TIME = "config_validation_time"
            const val TCP_CONNECTION_TIME = "tcp_connection_time"
            const val SSL_HANDSHAKE_TIME = "ssl_handshake_time"
            const val CERTIFICATE_VALIDATION_TIME = "certificate_validation_time"
            const val TOTAL_PROCESSING_TIME = "total_processing_time"
        }
    }
}

/**
 * 性能报告。
 */
data class PerformanceReport(
    val totalDuration: Duration,
    val metrics: Map<String, Duration>,
    val checkpoints: Map<String, Instant>,
    val averageMetricDuration: Duration,
    val metricCount: Int,
    val checkpointCount: Int,
) {
    /**
     * 获取特定指标。
     */
    fun getMetric(name: String): Duration? = metrics[name]

    /**
     * 获取特定检查点。
     */
    fun getCheckpoint(name: String): Instant? = checkpoints[name]

    /**
     * 检查是否有性能问题。
     */
    fun hasPerformanceIssues(threshold: Duration): Boolean {
        return metrics.values.any { it > threshold }
    }

    /**
     * 获取最慢的指标。
     */
    fun getSlowestMetric(): Pair<String, Duration>? {
        return metrics.maxByOrNull { it.value }?.let { it.key to it.value }
    }

    /**
     * 获取最快的指标。
     */
    fun getFastestMetric(): Pair<String, Duration>? {
        return metrics.minByOrNull { it.value }?.let { it.key to it.value }
    }

    /**
     * 转换为人类可读的字符串。
     */
    fun toHumanReadableString(): String =
        buildString {
            appendLine("Performance Report:")
            appendLine("  Total Duration: ${totalDuration.toMillis()}ms")
            appendLine("  Metrics Count: $metricCount")
            appendLine("  Checkpoints Count: $checkpointCount")
            appendLine("  Average Metric Duration: ${averageMetricDuration.toMillis()}ms")

            if (metrics.isNotEmpty()) {
                appendLine("  Metrics:")
                metrics.forEach { (name, duration) ->
                    appendLine("    $name: ${duration.toMillis()}ms")
                }
            }

            if (checkpoints.isNotEmpty()) {
                appendLine("  Checkpoints:")
                checkpoints.forEach { (name, instant) ->
                    appendLine("    $name: $instant")
                }
            }
        }
}
