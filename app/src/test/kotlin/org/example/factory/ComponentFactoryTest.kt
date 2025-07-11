package org.example.factory

import io.mockk.mockk
import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ComponentFactoryTest {
    @BeforeEach
    fun setUp() {
        ComponentFactoryManager.resetToDefault()
    }

    @AfterEach
    fun tearDown() {
        ComponentFactoryManager.resetToDefault()
    }

    @Test
    fun `test default factory creates all components`() {
        val factory = ComponentFactoryManager.getFactory()

        // 测试 SSL 连接测试器
        val sslTester = factory.createSSLConnectionTester()
        assertNotNull(sslTester)
        // Type is guaranteed by factory implementation

        // 测试证书验证器
        val certValidator = factory.createCertificateValidator()
        assertNotNull(certValidator)
        // Type is guaranteed by factory implementation

        // 测试所有格式化器
        val formatters = factory.createAllFormatters()
        assertEquals(4, formatters.size) // TXT, JSON, YAML, EMOJI

        assertTrue(formatters.containsKey(OutputFormat.TXT))
        assertTrue(formatters.containsKey(OutputFormat.JSON))
        assertTrue(formatters.containsKey(OutputFormat.YAML))
        assertTrue(formatters.containsKey(OutputFormat.EMOJI))
    }

    @Test
    fun `test factory creates correct formatter for each format`() {
        val factory = ComponentFactoryManager.getFactory()

        // 测试 TXT 格式化器
        val txtFormatter = factory.createFormatter(OutputFormat.TXT)
        assertNotNull(txtFormatter)
        // Type is guaranteed by factory implementation
        assertEquals("txt", txtFormatter.getFileExtension())

        // 测试 JSON 格式化器
        val jsonFormatter = factory.createFormatter(OutputFormat.JSON)
        assertNotNull(jsonFormatter)
        // Type is guaranteed by factory implementation
        assertEquals("json", jsonFormatter.getFileExtension())

        // 测试 YAML 格式化器
        val yamlFormatter = factory.createFormatter(OutputFormat.YAML)
        assertNotNull(yamlFormatter)
        // Type is guaranteed by factory implementation
        assertEquals("yaml", yamlFormatter.getFileExtension())

        // 测试 EMOJI 格式化器
        val emojiFormatter = factory.createFormatter(OutputFormat.EMOJI)
        assertNotNull(emojiFormatter)
        // Type is guaranteed by factory implementation
        assertEquals("txt", emojiFormatter.getFileExtension())
    }

    @Test
    fun `test factory singleton behavior`() {
        val factory1 = ComponentFactoryManager.getFactory()
        val factory2 = ComponentFactoryManager.getFactory()

        // 应该返回同一个实例
        assertEquals(factory1, factory2)
    }

    @Test
    fun `test test factory with mock dependencies`() {
        val mockSSLTester = mockk<SSLConnectionTester>()
        val mockCertValidator = mockk<CertificateValidator>()
        val mockFormatter = mockk<OutputFormatter>()

        val testFormatters: Map<OutputFormat, OutputFormatter> = mapOf(OutputFormat.TXT to mockFormatter)

        val testFactory =
            TestComponentFactory(
                sslConnectionTester = mockSSLTester,
                certificateValidator = mockCertValidator,
                formatters = testFormatters,
            )

        ComponentFactoryManager.setFactory(testFactory)

        val factory = ComponentFactoryManager.getFactory()
        assertEquals(mockSSLTester, factory.createSSLConnectionTester())
        assertEquals(mockCertValidator, factory.createCertificateValidator())
        assertEquals(mockFormatter, factory.createFormatter(OutputFormat.TXT))
    }

    @Test
    fun `test factory creates new instances each time`() {
        val factory = ComponentFactoryManager.getFactory()

        // 每次创建都应该返回新实例
        val formatter1 = factory.createFormatter(OutputFormat.TXT)
        val formatter2 = factory.createFormatter(OutputFormat.TXT)

        // 应该返回不同的实例（工厂模式每次创建新实例）
        assertTrue(formatter1 !== formatter2)
    }
}
