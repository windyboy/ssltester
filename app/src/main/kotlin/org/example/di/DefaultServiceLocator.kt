package org.example.di

import org.example.CertificateValidator
import org.example.DefaultSSLConnectionTester
import org.example.SSLConnectionTester
import org.example.formatter.EmojiTextOutputFormatter
import org.example.formatter.JsonOutputFormatter
import org.example.formatter.OutputFormatter
import org.example.formatter.TextOutputFormatter
import org.example.formatter.YamlOutputFormatter
import org.example.model.OutputFormat
import mu.KotlinLogging

private val logger = KotlinLogging.logger {}

/**
 * 默认服务定位器实现
 * 使用单例模式管理所有依赖，提供线程安全的访问
 */
class DefaultServiceLocator private constructor() : ServiceLocator {
    
    // 单例实例
    companion object {
        @Volatile
        private var instance: DefaultServiceLocator? = null
        
        fun getInstance(): DefaultServiceLocator {
            return instance ?: synchronized(this) {
                instance ?: DefaultServiceLocator().also { instance = it }
            }
        }
        
        fun reset() {
            synchronized(this) {
                instance?.shutdown()
                instance = null
            }
        }
    }
    
    // 缓存的依赖实例
    private var sslConnectionTester: SSLConnectionTester? = null
    private var certificateValidator: CertificateValidator? = null
    private val formatters = mutableMapOf<OutputFormat, OutputFormatter>()
    
    override fun getSSLConnectionTester(): SSLConnectionTester {
        return sslConnectionTester ?: synchronized(this) {
            sslConnectionTester ?: DefaultSSLConnectionTester().also { 
                sslConnectionTester = it 
                logger.debug { "Created new SSLConnectionTester instance" }
            }
        }
    }
    
    override fun getCertificateValidator(): CertificateValidator {
        return certificateValidator ?: synchronized(this) {
            certificateValidator ?: CertificateValidator().also { 
                certificateValidator = it 
                logger.debug { "Created new CertificateValidator instance" }
            }
        }
    }
    
    override fun getFormatter(format: OutputFormat): OutputFormatter {
        return formatters.getOrPut(format) {
            when (format) {
                OutputFormat.TXT -> TextOutputFormatter()
                OutputFormat.JSON -> JsonOutputFormatter()
                OutputFormat.YAML -> YamlOutputFormatter()
                OutputFormat.EMOJI -> EmojiTextOutputFormatter()
                OutputFormat.UNKNOWN -> TextOutputFormatter()
            }.also { 
                logger.debug { "Created new formatter for format: $format" }
            }
        }
    }
    
    override fun getAllFormatters(): Map<OutputFormat, OutputFormatter> {
        // 确保所有格式化器都已创建
        listOf(OutputFormat.TXT, OutputFormat.JSON, OutputFormat.YAML, OutputFormat.EMOJI).forEach { format ->
            getFormatter(format)
        }
        return formatters.toMap()
    }
    
    override fun shutdown() {
        synchronized(this) {
            logger.info { "Shutting down DefaultServiceLocator" }
            sslConnectionTester = null
            certificateValidator = null
            formatters.clear()
        }
    }
} 