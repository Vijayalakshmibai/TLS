FROM eclipse-temurin:21-jdk AS build

WORKDIR /workspace
COPY . .
RUN chmod +x mvnw && ./mvnw -B -Djava.version=21 -DskipTests package

FROM eclipse-temurin:25-jre

WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/target/tls-monitor-1.0.0-SNAPSHOT.jar /app/app.jar

ENV SERVER_PORT=8085
EXPOSE 8085
USER 10001:10001

# Respect Railway's dynamic PORT if set, otherwise fall back to SERVER_PORT (8085).
# Provide DB_URL, DB_USERNAME, DB_PASSWORD, MAIL_USERNAME, and MAIL_APP_PASSWORD at runtime.
ENTRYPOINT ["sh", "-c", "java -XX:MaxRAMPercentage=75.0 -Dserver.port=${PORT:-${SERVER_PORT:-8085}} -jar /app/app.jar"]
