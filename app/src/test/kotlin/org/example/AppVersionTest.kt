package org.example

import kotlin.test.Test
import kotlin.test.assertEquals

class AppVersionTest {
    @Test
    fun `test version constant`() {
        assertEquals("0.0.5", AppVersion.VERSION)
    }
}
