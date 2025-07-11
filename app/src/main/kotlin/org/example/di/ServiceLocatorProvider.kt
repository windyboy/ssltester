package org.example.di

import mu.KotlinLogging

private val logger = KotlinLogging.logger {}

/**
 * 服务定位器提供者
 * 管理全局的服务定位器实例，支持运行时切换
 */
object ServiceLocatorProvider {
    
    @Volatile
    private var currentLocator: ServiceLocator? = null
    
    /**
     * 获取当前的服务定位器
     */
    fun getServiceLocator(): ServiceLocator {
        return currentLocator ?: synchronized(this) {
            currentLocator ?: DefaultServiceLocator.getInstance().also { 
                currentLocator = it 
                logger.debug { "Initialized default ServiceLocator" }
            }
        }
    }
    
    /**
     * 设置服务定位器
     * 主要用于测试环境
     */
    fun setServiceLocator(locator: ServiceLocator) {
        synchronized(this) {
            currentLocator?.shutdown()
            currentLocator = locator
            logger.debug { "ServiceLocator replaced with: ${locator::class.simpleName}" }
        }
    }
    
    /**
     * 重置为默认服务定位器
     */
    fun resetToDefault() {
        synchronized(this) {
            currentLocator?.shutdown()
            currentLocator = null
            logger.debug { "ServiceLocator reset to default" }
        }
    }
    
    /**
     * 清理资源
     */
    fun shutdown() {
        synchronized(this) {
            currentLocator?.shutdown()
            currentLocator = null
            logger.info { "ServiceLocatorProvider shutdown" }
        }
    }
} 