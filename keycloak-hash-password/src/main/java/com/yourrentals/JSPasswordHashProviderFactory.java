package com.yourrentals;

import org.keycloak.Config.Scope;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class JSPasswordHashProviderFactory implements PasswordHashProviderFactory {
	public static final String ID = "js-password-hash";

	@Override
	public PasswordHashProvider create(KeycloakSession session) {
		return new JSPasswordHashProvider(getId());
	}

	@Override
	public void init(Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return ID;
	}
}
