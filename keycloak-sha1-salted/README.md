# keycloak-sha1-salted
Add salted SHA1 hashing support to Keycloak. ie. you're migrating to Keycloak and need to import legacy passwords stored as SHA-1 salted hashes.

## Requirements
- Java 11
- Maven 3.6

## Building

- Run `mvn package`
- JAR archive is generated in `./target/keycloak-sha1.jar`

## Deploying to Keycloak

1. Move the built JAR file to Keycloak's directory `standalone/deployments/` (on Keycloak under Docker: `/opt/jboss/keycloak/standalone/deployments`)
2. Watch the `standalone/deployments/` for the file `keycloak-sha1.jar.deployed`

:warning: If you find instead the file `keycloak-sha1.jar.failed`, you can run the command `cat keycloak-sha1.jar.failed` to find out what went wrong with your deployment.

## How to use
Use algorithm `sha1-salted` when importing users through JSON. Below an example with
* password `123456789`
* salt `qwerty` (base64-encoded: `cXdlcnR5`)

JSON:

    {
      "realm": "master",
      "users": [
        {
          "username": "user1",
          "enabled": true,
          "totp": false,
          "emailVerified": true,
          "firstName": "user1",
          "lastName": "user1",
          "email": "user1@test.com",
          "credentials": [
            {
              "algorithm": "sha1-salted",
              "hashedSaltedValue": "9282d06b77e03989da6c0d86479ba73ac8691cfc",
              "salt": "cXdlcnR5",
              "hashIterations": 1,
              "type": "password"
            }
          ],
          "disableableCredentialTypes": [],
          "requiredActions": [],
          "realmRoles": [
            "offline_access",
            "uma_authorization"
          ],
          "clientRoles": {
            "account": [
              "manage-account",
              "view-profile"
            ]
          }
        }
      ]
    }
