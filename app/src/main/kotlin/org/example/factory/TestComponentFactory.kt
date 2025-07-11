package org.example.factory

import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat

/**
 * 测试用组件工厂
 * 支持注入模拟对象，便于单元测试
 */
class TestComponentFactory(
    private val sslConnectionTester: SSLConnectionTester? = null,
    private val certificateValidator: CertificateValidator? = null,
    private val formatters: Map<OutputFormat, OutputFormatter> = emptyMap(),
) : ComponentFactory {
    override fun createSSLConnectionTester(): SSLConnectionTester {
        return sslConnectionTester ?: throw IllegalStateException(
            "SSLConnectionTester not provided to TestComponentFactory",
        )
    }

    override fun createCertificateValidator(): CertificateValidator {
        return certificateValidator ?: throw IllegalStateException(
            "CertificateValidator not provided to TestComponentFactory",
        )
    }

    override fun createFormatter(format: OutputFormat): OutputFormatter {
        return formatters[format] ?: throw IllegalStateException(
            "Formatter for format $format not provided to TestComponentFactory",
        )
    }

    override fun createAllFormatters(): Map<OutputFormat, OutputFormatter> {
        return formatters
    }
}
