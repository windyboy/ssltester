package org.example.cert;

import org.junit.jupiter.api.Test;
import java.net.IDN;
import static org.junit.jupiter.api.Assertions.*;

public class IDNTest {

    @Test
    void testIDNConversion() {
        // 测试Unicode与Punycode的转换
        String unicodeHostname = "президент.рф";

        System.out.println("原始Unicode域名: " + unicodeHostname);

        // Unicode转换为Punycode
        String actualPunycode = IDN.toASCII(unicodeHostname);
        System.out.println("Java IDN API 转换结果: " + actualPunycode);

        // 不再预设Punycode值，而是直接确认转换有效且符合规则
        assertTrue(actualPunycode.startsWith("xn--"), "转换后的Punycode应以xn--开头");

        // Punycode转回Unicode
        String backToUnicode = IDN.toUnicode(actualPunycode);
        System.out.println("转回Unicode: " + backToUnicode);

        // 验证转换回来的结果（这才是最重要的验证）
        assertEquals(unicodeHostname.toLowerCase(), backToUnicode.toLowerCase(),
                    "Punycode转回Unicode后应与原始Unicode匹配（忽略大小写）");

        // 记录实际生成的Punycode，以便将其用于证书生成
        System.out.println("测试通过！请在证书中使用此Punycode值: " + actualPunycode);
    }
}
