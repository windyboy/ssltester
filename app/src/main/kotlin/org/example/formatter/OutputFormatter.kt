package org.example.formatter

import org.example.model.SSLConnection

/**
 * 输出格式化器接口
 * 统一所有输出格式化器的接口
 */
interface OutputFormatter {
    /**
     * 格式化 SSL 连接结果
     * @param connection SSL 连接结果
     * @return 格式化后的字符串
     */
    fun format(connection: SSLConnection): String

    /**
     * 获取文件扩展名
     * @return 文件扩展名（不包含点）
     */
    fun getFileExtension(): String
}
