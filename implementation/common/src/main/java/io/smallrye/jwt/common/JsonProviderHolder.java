package io.smallrye.jwt.common;

import java.util.Map;

import jakarta.json.JsonConfig;
import jakarta.json.JsonReaderFactory;
import jakarta.json.spi.JsonProvider;

public final class JsonProviderHolder {

    private static final JsonProvider JSON_PROVIDER = JsonProvider.provider();

    // RFC 7519, section 4: the claim names must be unique, a JSON object with duplicate names at any nesting
    // level is rejected, as jose4j did, instead of the last duplicate silently winning
    private static final JsonReaderFactory JSON_READER_FACTORY = JSON_PROVIDER
            .createReaderFactory(Map.of(JsonConfig.KEY_STRATEGY, JsonConfig.KeyStrategy.NONE));

    private JsonProviderHolder() {
    }

    public static JsonProvider jsonProvider() {
        return JSON_PROVIDER;
    }

    /**
     * JSON reader factory which rejects JSON objects with duplicate names.
     *
     * @return the reader factory
     */
    public static JsonReaderFactory jsonReaderFactory() {
        return JSON_READER_FACTORY;
    }
}