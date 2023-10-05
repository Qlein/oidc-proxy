FROM maven:3.9.0-eclipse-temurin-19-focal as build

COPY src /home/app/src
COPY pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package


FROM eclipse-temurin:19-focal

RUN mkdir /app

COPY --from=build /home/app/target/*-fat.jar /app/application.jar

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom","-jar","/app/application.jar"]
