package org.example

import mu.KotlinLogging
import org.example.cli.SSLTestCommand
import org.example.di.ServiceLocatorProvider
import picocli.CommandLine
import kotlin.system.exitProcess

/**
 * SSL测试工具主应用程序入口。
 * 负责初始化命令行工具并启动执行。
 */
private val logger = KotlinLogging.logger {}

/**
 * 程序入口函数。
 * @param args 命令行参数
 */
fun main(args: Array<String>) {
    try {
        // 使用依赖注入创建命令实例
        val command = SSLTestCommand()
        val exitCode = CommandLine(command).execute(*args)

        // 清理资源
        ServiceLocatorProvider.shutdown()

        exitProcess(exitCode)
    } catch (e: Exception) {
        logger.error(e) { "Application failed to start" }

        // 确保在异常情况下也清理资源
        ServiceLocatorProvider.shutdown()

        exitProcess(1)
    }
}
