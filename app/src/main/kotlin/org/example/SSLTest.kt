package org.example

import mu.KotlinLogging
import org.example.cli.SSLTestCommand
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
        // 直接 new 命令实例
        val command = SSLTestCommand()
        val exitCode = CommandLine(command).execute(*args)
        exitProcess(exitCode)
    } catch (e: Exception) {
        logger.error(e) { "Application failed to start" }
        exitProcess(1)
    }
}
