package org.example.factory

import mu.KotlinLogging

private val logger = KotlinLogging.logger {}

/**
 * 组件工厂管理器
 * 管理全局的组件工厂实例，支持运行时切换
 */
object ComponentFactoryManager {
    @Volatile
    private var currentFactory: ComponentFactory? = null

    /**
     * 获取当前的组件工厂
     */
    fun getFactory(): ComponentFactory {
        return currentFactory ?: synchronized(this) {
            currentFactory ?: DefaultComponentFactory().also {
                currentFactory = it
                logger.debug { "Initialized default ComponentFactory" }
            }
        }
    }

    /**
     * 设置组件工厂
     * 主要用于测试环境
     */
    fun setFactory(factory: ComponentFactory) {
        synchronized(this) {
            currentFactory = factory
            logger.debug { "ComponentFactory replaced with: ${factory::class.simpleName}" }
        }
    }

    /**
     * 重置为默认工厂
     */
    fun resetToDefault() {
        synchronized(this) {
            currentFactory = null
            logger.debug { "ComponentFactory reset to default" }
        }
    }
}
