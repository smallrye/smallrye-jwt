package io.smallrye.jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.json.spi.JsonProvider;

public class JsonUtils {

    private static final JsonProvider JSON_PROVIDER = JsonProvider.provider();

    private JsonUtils() {
    }

    public static JsonObject replaceMap(Map<String, Object> map) {
        JsonObjectBuilder builder = JSON_PROVIDER.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if (entryValue instanceof Map) {
                @SuppressWarnings("unchecked")
                JsonObject entryJsonObject = replaceMap((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if (entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if (entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if (entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if (entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if (entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    private static JsonArray toJsonArray(Collection<?> collection) {
        JsonArrayBuilder arrayBuilder = JSON_PROVIDER.createArrayBuilder();

        for (Object element : collection) {
            if (element instanceof String) {
                arrayBuilder.add(element.toString());
            } else if (element == null) {
                arrayBuilder.add(JsonValue.NULL);
            } else {
                JsonValue jvalue = wrapValue(element);
                arrayBuilder.add(jvalue);
            }
        }

        return arrayBuilder.build();
    }

    public static JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;

        if (value instanceof JsonValue) {
            // This may already be a JsonValue
            jsonValue = (JsonValue) value;
        } else if (value instanceof String) {
            jsonValue = JSON_PROVIDER.createValue(value.toString());
        } else if ((value instanceof Long) || (value instanceof Integer)) {
            jsonValue = JSON_PROVIDER.createValue(((Number) value).longValue());
        } else if (value instanceof Number) {
            jsonValue = JSON_PROVIDER.createValue(((Number) value).doubleValue());
        } else if (value instanceof Boolean) {
            jsonValue = (Boolean) value ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof Collection) {
            jsonValue = toJsonArray((Collection<?>) value);
        } else if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            JsonObject entryJsonObject = replaceMap((Map<String, Object>) value);
            jsonValue = entryJsonObject;
        }

        return jsonValue;
    }

    /**
     * Manual converter to convert Json type to supported Java types in the spec.
     *
     * @param klass Class to convert the value to
     * @param value the value to be converted
     * @return converted Object
     */
    public static Object convert(final Class<?> klass, final Object value) {
        if (klass == null) {
            return value;
        }

        if (klass.isAssignableFrom(String.class) && value instanceof JsonString) {
            return value.toString();
        }

        // We dont convert String to JsonString in io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal.fixJoseTypes
        if (klass.isAssignableFrom(JsonString.class) && value instanceof String) {
            return JsonUtils.wrapValue(value);
        }

        if (klass.isAssignableFrom(Long.class) && value instanceof JsonNumber) {
            return ((JsonNumber) value).longValue();
        }

        if (klass.isAssignableFrom(Boolean.class)) {
            if (value == JsonValue.TRUE) {
                return Boolean.TRUE;
            }

            if (value == JsonValue.FALSE) {
                return Boolean.FALSE;
            }

            if (value instanceof JsonString) {
                return Boolean.valueOf(value.toString());
            }
        }

        if (klass.isAssignableFrom(Set.class) && value instanceof JsonArray) {
            return new HashSet<>(((JsonArray) value).getValuesAs(jsonValue -> {
                if (jsonValue instanceof JsonString) {
                    return ((JsonString) jsonValue).getString();
                }
                return jsonValue.toString();
            }));
        }

        return value;
    }
}
