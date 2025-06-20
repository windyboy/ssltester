package org.example.config

import org.example.cli.SSLTestCommand
import org.example.output.JsonOutputFormatter
import org.example.output.OutputFormatter
import org.example.output.TextOutputFormatter
import org.example.output.YamlOutputFormatter
import org.example.service.SSLConnectionTester
import org.example.service.SSLConnectionTesterImpl
import org.koin.core.qualifier.named
import org.koin.dsl.module

val appModule =
    module {
        // Core services
        single<SSLConnectionTester> { SSLConnectionTesterImpl() }

        // Output formatters
        single<OutputFormatter>(qualifier = named("txt")) { TextOutputFormatter() }
        single<OutputFormatter>(qualifier = named("json")) { JsonOutputFormatter() }
        single<OutputFormatter>(qualifier = named("yaml")) { YamlOutputFormatter() }

        // CLI Commands
        single { SSLTestCommand() }
    }
