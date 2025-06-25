package org.example

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 主函数集成测试
 * 测试主函数的命令行参数处理和输出
 */
class SSLTestMainIT {
    @Test
    fun `test main function with help flag`() {
        val process =
            ProcessBuilder()
                .command("java", "-jar", "app/build/libs/app-all.jar", "--help")
                .start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        assertEquals(0, exitCode)
        assertTrue(output.contains("Usage: ssl-test"))
        assertTrue(output.contains("Test SSL/TLS connections"))
    }

    @Test
    fun `test main function with version flag`() {
        val process =
            ProcessBuilder()
                .command("java", "-jar", "app/build/libs/app-all.jar", "--version")
                .start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        assertEquals(0, exitCode)
        assertTrue(output.contains("0.0.2"))
    }

    @Test
    fun `test main function with invalid host`() {
        val process =
            ProcessBuilder()
                .command("java", "-jar", "app/build/libs/app-all.jar", "nonexistent.example.com")
                .start()

        val exitCode = process.waitFor()

        assertEquals(1, exitCode)
    }

    @Test
    fun `test main function with output to file`(
        @TempDir tempDir: Path,
    ) {
        val outputFile = tempDir.resolve("test_output.txt")

        val process =
            ProcessBuilder()
                .command("java", "-jar", "app/build/libs/app-all.jar", "example.com", "-o", outputFile.toString())
                .start()

        val exitCode = process.waitFor()

        // 即使连接失败，文件也应该被创建
        assertTrue(outputFile.toFile().exists())
    }
}
