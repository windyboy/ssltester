package org.example.di

import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat

/**
 * 测试用服务定位器
 * 支持注入模拟对象，便于单元测试
 */
class TestServiceLocator(
    private val sslConnectionTester: SSLConnectionTester? = null,
    private val certificateValidator: CertificateValidator? = null,
    private val formatters: Map<OutputFormat, OutputFormatter> = emptyMap(),
) : ServiceLocator {
    override fun getSSLConnectionTester(): SSLConnectionTester {
        return sslConnectionTester ?: throw IllegalStateException(
            "SSLConnectionTester not provided to TestServiceLocator",
        )
    }

    override fun getCertificateValidator(): CertificateValidator {
        return certificateValidator ?: throw IllegalStateException(
            "CertificateValidator not provided to TestServiceLocator",
        )
    }

    override fun getFormatter(format: OutputFormat): OutputFormatter {
        return formatters[format] ?: throw IllegalStateException(
            "Formatter for format $format not provided to TestServiceLocator",
        )
    }

    override fun getAllFormatters(): Map<OutputFormat, OutputFormatter> {
        return formatters
    }

    override fun shutdown() {
        // 测试环境不需要特殊清理
    }
}
