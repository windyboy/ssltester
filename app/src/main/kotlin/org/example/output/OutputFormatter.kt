package org.example.output

import org.example.model.SSLConnection

sealed interface OutputFormatter {
    fun format(connection: SSLConnection): String

    fun getFileExtension(): String
}
