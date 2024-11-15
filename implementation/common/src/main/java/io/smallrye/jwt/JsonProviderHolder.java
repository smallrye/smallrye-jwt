package io.smallrye.jwt;

import jakarta.json.spi.JsonProvider;

public final class JsonProviderHolder {

    private static final JsonProvider JSON_PROVIDER = JsonProvider.provider();

    private JsonProviderHolder() {
    }

    public static JsonProvider jsonProvider() {
        return JSON_PROVIDER;
    }
}