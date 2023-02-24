/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt;

import static jakarta.json.JsonValue.NULL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

import org.junit.jupiter.api.Test;

class JsonUtilsTests {
    @Test
    void wrapClaimValueJsonValue() {
        JsonValue expResult = JsonValue.TRUE;
        JsonValue result = JsonUtils.wrapValue(expResult);

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueString() {
        JsonValue expResult = Json.createValue("string");
        JsonValue result = JsonUtils.wrapValue("string");

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueNumber() {
        JsonValue expResult = Json.createValue(1);
        JsonValue result = JsonUtils.wrapValue(1);

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueNumberDecimal() {
        JsonValue expResult = Json.createValue(1.1d);
        JsonValue result = JsonUtils.wrapValue(1.1d);

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueBoolean() {
        JsonValue expResult = JsonValue.FALSE;
        JsonValue result = JsonUtils.wrapValue(false);

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueCollection() {
        JsonArray expResult = Json.createArrayBuilder()
                .add("a")
                .add("b")
                .add("c")
                .build();
        JsonValue result = JsonUtils.wrapValue(Arrays.asList("a", "b", "c"));

        assertTrue(result instanceof JsonArray);
        JsonArray resultArray = result.asJsonArray();
        assertEquals(expResult.size(), resultArray.size());
        assertEquals(expResult.getString(0), resultArray.getString(0));
        assertEquals(expResult.getString(1), resultArray.getString(1));
        assertEquals(expResult.getString(2), resultArray.getString(2));
    }

    @Test
    void wrapClaimValueMap() {
        JsonObject expResult = Json.createObjectBuilder()
                .add("a", "a")
                .add("b", "b")
                .add("c", "c")
                .build();

        Map<String, String> value = new HashMap<>();
        value.put("a", "a");
        value.put("b", "b");
        value.put("c", "c");
        JsonValue result = JsonUtils.wrapValue(value);

        assertTrue(result instanceof JsonObject);
        JsonObject resultObject = result.asJsonObject();
        assertEquals(expResult, resultObject);
    }

    @Test
    void wrapClaimValueNull() {
        JsonValue expResult = null;
        JsonValue result = JsonUtils.wrapValue(null);

        assertEquals(expResult, result);
    }

    @Test
    void wrapClaimValueCollectionWithNull() {
        JsonArray expResult = Json.createArrayBuilder()
                .add(NULL)
                .build();
        JsonValue result = JsonUtils.wrapValue(Arrays.asList((String) null));

        assertTrue(result instanceof JsonArray);
        JsonArray resultArray = result.asJsonArray();
        assertEquals(expResult.size(), resultArray.size());
        assertEquals(expResult.get(0), resultArray.get(0));
    }

    @Test
    void wrapClaimValueMapWithNull() {
        JsonObject expResult = Json.createObjectBuilder()
                .build();

        Map<String, String> value = new HashMap<>();
        value.put("a", null);
        JsonValue result = JsonUtils.wrapValue(value);

        assertTrue(result instanceof JsonObject);
        JsonObject resultObject = result.asJsonObject();
        assertEquals(expResult, resultObject);
    }
}
