package org.example.output

import org.example.model.SSLConnection

interface OutputFormatter {
    fun format(connection: SSLConnection): String

    fun getFileExtension(): String
}
