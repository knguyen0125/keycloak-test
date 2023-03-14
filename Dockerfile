FROM alpine/curl:latest AS curl

ENV KEYCLOAK_HOME /opt/keycloak
ENV KEYCLOAK_BCRYPT_VERSION 1.5.3
RUN curl -L https://github.com/leroyguillaume/keycloak-bcrypt/releases/download/${KEYCLOAK_BCRYPT_VERSION}/keycloak-bcrypt-${KEYCLOAK_BCRYPT_VERSION}.jar > keycloak-bcrypt.jar
RUN curl -L https://github.com/mathsalmi/keycloak-sha1/releases/download/1.0/keycloak-sha1.jar > keycloak-sha1.jar

FROM quay.io/keycloak/keycloak:21.0.1 AS builder

COPY --from=curl keycloak-bcrypt.jar /opt/keycloak/providers/keycloak-bcrypt.jar
COPY ./keycloak-sha1.jar /opt/keycloak/providers/keycloak-sha1.jar
