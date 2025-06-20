package org.example

import mu.KotlinLogging
import org.example.cli.SSLTestCommand
import org.example.config.appModule
import org.koin.core.context.startKoin
import picocli.CommandLine
import kotlin.system.exitProcess

private val logger = KotlinLogging.logger {}

fun main(args: Array<String>) {
    try {
        // Initialize Koin
        val koin =
            startKoin {
                printLogger()
                modules(appModule)
            }.koin

        // Get command instance from Koin
        val command = koin.get<SSLTestCommand>()

        // Execute command
        val exitCode = CommandLine(command).execute(*args)
        exitProcess(exitCode)
    } catch (e: Exception) {
        logger.error(e) { "Application failed to start" }
        exitProcess(1)
    }
}
