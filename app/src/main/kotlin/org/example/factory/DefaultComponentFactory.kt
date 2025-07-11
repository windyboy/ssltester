package org.example.factory

import mu.KotlinLogging
import org.example.CertificateValidator
import org.example.DefaultSSLConnectionTester
import org.example.SSLConnectionTester
import org.example.formatter.EmojiTextOutputFormatter
import org.example.formatter.JsonOutputFormatter
import org.example.formatter.OutputFormatter
import org.example.formatter.TextOutputFormatter
import org.example.formatter.YamlOutputFormatter
import org.example.model.OutputFormat

private val logger = KotlinLogging.logger {}

/**
 * 默认组件工厂实现
 * 负责创建应用中的各种组件实例
 */
class DefaultComponentFactory : ComponentFactory {
    override fun createSSLConnectionTester(): SSLConnectionTester {
        logger.debug { "Creating new SSLConnectionTester instance" }
        return DefaultSSLConnectionTester()
    }

    override fun createCertificateValidator(): CertificateValidator {
        logger.debug { "Creating new CertificateValidator instance" }
        return CertificateValidator()
    }

    override fun createFormatter(format: OutputFormat): OutputFormatter {
        logger.debug { "Creating new formatter for format: $format" }
        return when (format) {
            OutputFormat.TXT -> TextOutputFormatter()
            OutputFormat.JSON -> JsonOutputFormatter()
            OutputFormat.YAML -> YamlOutputFormatter()
            OutputFormat.EMOJI -> EmojiTextOutputFormatter()
            OutputFormat.UNKNOWN -> TextOutputFormatter()
        }
    }

    override fun createAllFormatters(): Map<OutputFormat, OutputFormatter> {
        return listOf(OutputFormat.TXT, OutputFormat.JSON, OutputFormat.YAML, OutputFormat.EMOJI)
            .associateWith { createFormatter(it) }
    }
}
