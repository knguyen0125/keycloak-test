FROM maven:3.6.3-jdk-11 AS maven

COPY keycloak-hash-password /home/app
RUN mvn -f /home/app/pom.xml clean package

FROM quay.io/keycloak/keycloak:21.0.1 AS builder

COPY --from=maven /home/app/target/keycloak-password-hash.jar /opt/keycloak/providers/keycloak-password-hash.jar
