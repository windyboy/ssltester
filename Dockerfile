FROM eclipse-temurin:17-jre-alpine

WORKDIR /app
ARG JAR_FILE
COPY ${JAR_FILE} app.jar

# Create a non-root user to run the application
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT ["java", "-jar", "app.jar"] 
