# SSL Test Tool Docker Image
# 基于Eclipse Temurin Java 21运行时环境
FROM eclipse-temurin:21-jre-alpine

# 设置工作目录
WORKDIR /app

# 构建参数：JAR文件路径
ARG JAR_FILE

# 复制JAR文件到容器
COPY ${JAR_FILE} app.jar

# 创建非root用户来运行应用程序
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# 切换到非root用户
USER appuser

# 设置JVM参数以优化容器环境
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"

# 应用程序入口点
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"] 
