package org.example.model

import org.example.model.OutputFormat
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.Test
import kotlin.test.assertNotEquals

class OutputFormatTest {
    @Test
    fun `test TXT format`() {
        val format = OutputFormat.TXT
        assertEquals("TXT", format.value)
    }

    @Test
    fun `test JSON format`() {
        val format = OutputFormat.JSON
        assertEquals("JSON", format.value)
    }

    @Test
    fun `test YAML format`() {
        val format = OutputFormat.YAML
        assertEquals("YAML", format.value)
    }

    @Test
    fun `test UNKNOWN format`() {
        val format = OutputFormat.UNKNOWN
        assertEquals("UNKNOWN", format.value)
    }

    @Test
    fun `test valueOf with TXT lowercase`() {
        val result = OutputFormat.valueOf("txt")
        assertEquals(OutputFormat.TXT, result)
    }

    @Test
    fun `test valueOf with TXT uppercase`() {
        val result = OutputFormat.valueOf("TXT")
        assertEquals(OutputFormat.TXT, result)
    }

    @Test
    fun `test valueOf with TXT mixed case`() {
        val result = OutputFormat.valueOf("Txt")
        assertEquals(OutputFormat.TXT, result)
    }

    @Test
    fun `test valueOf with JSON lowercase`() {
        val result = OutputFormat.valueOf("json")
        assertEquals(OutputFormat.JSON, result)
    }

    @Test
    fun `test valueOf with JSON uppercase`() {
        val result = OutputFormat.valueOf("JSON")
        assertEquals(OutputFormat.JSON, result)
    }

    @Test
    fun `test valueOf with JSON mixed case`() {
        val result = OutputFormat.valueOf("Json")
        assertEquals(OutputFormat.JSON, result)
    }

    @Test
    fun `test valueOf with YAML lowercase`() {
        val result = OutputFormat.valueOf("yaml")
        assertEquals(OutputFormat.YAML, result)
    }

    @Test
    fun `test valueOf with YAML uppercase`() {
        val result = OutputFormat.valueOf("YAML")
        assertEquals(OutputFormat.YAML, result)
    }

    @Test
    fun `test valueOf with YAML mixed case`() {
        val result = OutputFormat.valueOf("Yaml")
        assertEquals(OutputFormat.YAML, result)
    }

    @Test
    fun `test valueOf with invalid format`() {
        val result = OutputFormat.valueOf("invalid")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with empty string`() {
        val result = OutputFormat.valueOf("")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with whitespace`() {
        val result = OutputFormat.valueOf("  txt  ")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with special characters`() {
        val result = OutputFormat.valueOf("txt!")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with numbers`() {
        val result = OutputFormat.valueOf("123")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with partial match`() {
        val result = OutputFormat.valueOf("tx")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with extra characters`() {
        val result = OutputFormat.valueOf("txtx")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with XML format`() {
        val result = OutputFormat.valueOf("xml")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with CSV format`() {
        val result = OutputFormat.valueOf("csv")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with HTML format`() {
        val result = OutputFormat.valueOf("html")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with very long string`() {
        val longString = "a".repeat(100)
        val result = OutputFormat.valueOf(longString.uppercase())

        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with unicode characters`() {
        val result = OutputFormat.valueOf("tëxt")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test valueOf with emoji`() {
        val result = OutputFormat.valueOf("txt😀")
        assertEquals(OutputFormat.UNKNOWN, result)
    }

    @Test
    fun `test format equality`() {
        val format1: OutputFormat = OutputFormat.TXT
        val format2: OutputFormat = OutputFormat.TXT
        val format3: OutputFormat = OutputFormat.JSON

        assertEquals(format1, format2)
        assertNotEquals<OutputFormat>(format1, format3)
    }

    @Test
    fun `test format hash code`() {
        val format1: OutputFormat = OutputFormat.TXT
        val format2: OutputFormat = OutputFormat.TXT
        val format3: OutputFormat = OutputFormat.JSON

        assertEquals(format1.hashCode(), format2.hashCode())
        assertNotEquals<Int>(format1.hashCode(), format3.hashCode())
    }

    @Test
    fun `test format toString`() {
        val format = OutputFormat.TXT
        assertTrue(format.toString().contains("TXT"))
    }

    @Test
    fun `test all format values`() {
        val formats =
            listOf(
                OutputFormat.TXT,
                OutputFormat.JSON,
                OutputFormat.YAML,
                OutputFormat.UNKNOWN,
            )

        assertEquals(4, formats.size)
        assertTrue(formats.contains(OutputFormat.TXT))
        assertTrue(formats.contains(OutputFormat.JSON))
        assertTrue(formats.contains(OutputFormat.YAML))
        assertTrue(formats.contains(OutputFormat.UNKNOWN))
    }

    @Test
    fun `test format value uniqueness`() {
        val values =
            listOf(
                OutputFormat.TXT.value,
                OutputFormat.JSON.value,
                OutputFormat.YAML.value,
                OutputFormat.UNKNOWN.value,
            )

        assertEquals(values.size, values.toSet().size) // All values should be unique
    }

    @Test
    fun `test format value consistency`() {
        val txt1 = OutputFormat.valueOf("txt")
        val txt2 = OutputFormat.valueOf("TXT")
        val txt3 = OutputFormat.valueOf("Txt")

        assertEquals(txt1, txt2)
        assertEquals(txt2, txt3)
        assertEquals(txt1, txt3)
    }

    @Test
    fun `test format value case sensitivity`() {
        val lowercase = OutputFormat.valueOf("txt")
        val uppercase = OutputFormat.valueOf("TXT")
        val mixed = OutputFormat.valueOf("Txt")

        assertEquals(lowercase, uppercase)
        assertEquals(uppercase, mixed)
        assertEquals(lowercase, mixed)
    }

    @Test
    fun `test format value edge cases`() {
        // Test with single character
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("t"))

        // Test with very long valid format
        val longTxt = "txt".repeat(100)
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf(longTxt))

        // Test with only spaces
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("   "))

        // Test with tabs and newlines
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("\t\n"))
    }

    @Test
    fun `test format value with leading zeros`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("0txt"))
    }

    @Test
    fun `test format value with trailing zeros`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt0"))
    }

    @Test
    fun `test format value with underscores`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt_json"))
    }

    @Test
    fun `test format value with hyphens`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt-json"))
    }

    @Test
    fun `test format value with dots`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt.json"))
    }

    @Test
    fun `test format value with slashes`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt/json"))
    }

    @Test
    fun `test format value with backslashes`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt\\json"))
    }

    @Test
    fun `test format value with parentheses`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt(json)"))
    }

    @Test
    fun `test format value with brackets`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt[json]"))
    }

    @Test
    fun `test format value with braces`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("txt{json}"))
    }

    @Test
    fun `test format value with quotes`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("\"txt\""))
    }

    @Test
    fun `test format value with single quotes`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("'txt'"))
    }

    @Test
    fun `test format value with backticks`() {
        assertEquals(OutputFormat.UNKNOWN, OutputFormat.valueOf("`txt`"))
    }
}
