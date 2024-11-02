FROM maven:3.9.9-eclipse-temurin-21-jammy  as build

RUN mkdir /home/app/

COPY pom.xml /home/app/pom.xml
RUN mvn -f /home/app/pom.xml dependency:resolve

COPY src /home/app/src
RUN mvn -f /home/app/pom.xml clean package


FROM eclipse-temurin:21.0.4_7-jre-jammy

RUN mkdir /app

COPY --from=build /home/app/target/*-fat.jar /app/application.jar

ENV JAVA_OPTS "-Xmx16m"

ENTRYPOINT java $JAVA_OPTS -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory -Djava.security.egd=file:/dev/./urandom -jar /app/application.jar
