package io.smallrye.jwt.build.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.build.JwtException;

/**
 * JWT Token Signing Utilities
 */
public class JwtSigningUtils {

    private JwtSigningUtils() {
        // no-op: utility class
    }

    public static String signWithPemKey(String pemKeyLocation, String jwtLocation) {
        return signWithPemKey(pemKeyLocation, (String) null, jwtLocation);
    }

    public static String signWithPemKey(String pemKeyLocation, String keyId, String jwtLocation) {
        return signWithPemKey(pemKeyLocation, kidToMap(keyId), jwtLocation);
    }

    public static String signWithPemKey(String pemKeyLocation, Map<String, Object> headers, String jwtLocation) {
        return readClaimsAndSign(readPrivatePemKey(pemKeyLocation), headers, jwtLocation);
    }

    public static String signWithPemKey(String pemKeyLocation, Map<String, Object> claims) {
        return signWithPemKey(pemKeyLocation, (String) null, claims);
    }

    public static String signWithPemKey(String pemKeyLocation, String keyId, Map<String, Object> claims) {
        return signWithPemKey(pemKeyLocation, kidToMap(keyId), claims);
    }

    public static String signWithPemKey(String pemKeyLocation, Map<String, Object> headers, Map<String, Object> claims) {
        return convertToClaimsAndSign(readPrivatePemKey(pemKeyLocation), headers, claims);
    }

    public static String signWithJwk(String jwkLocation, String jwtLocation) {
        return signWithJwk(jwkLocation, Collections.emptyMap(), jwtLocation);
    }

    public static String signWithJwk(String jwkLocation, Map<String, Object> headers, String jwtLocation) {
        return readClaimsAndSignWithJwk(createJsonWebKey(readJsonContent(jwkLocation)), headers, jwtLocation);
    }

    public static String signWithJwk(String jwkLocation, Map<String, Object> claims) {
        return signWithJwk(jwkLocation, Collections.emptyMap(), claims);
    }

    public static String signWithJwk(String jwkLocation, Map<String, Object> headers, Map<String, Object> claims) {
        return convertToClaimsAndSignWithJwk(createJsonWebKey(readJsonContent(jwkLocation)), headers, claims);
    }

    public static String signWithJwkFromSet(String jwkSetLocation, String keyId, String jwtLocation) {
        return signWithJwkFromSet(jwkSetLocation, kidToMap(keyId), jwtLocation);
    }

    public static String signWithJwkFromSet(String jwkSetLocation, Map<String, Object> headers, String jwtLocation) {
        JsonWebKey jwk = findJsonWebKeyInSet(readJsonContent(jwkSetLocation), (String) headers.get("kid"));
        return readClaimsAndSignWithJwk(jwk, headers, jwtLocation);
    }

    public static String signWithJwkFromSet(String jwkSetLocation, String keyId, Map<String, Object> claims) {
        return signWithJwkFromSet(jwkSetLocation, kidToMap(keyId), claims);
    }

    public static String signWithJwkFromSet(String jwkSetLocation, Map<String, Object> headers, Map<String, Object> claims) {
        JsonWebKey jwk = findJsonWebKeyInSet(readJsonContent(jwkSetLocation), (String) headers.get("kid"));
        return convertToClaimsAndSignWithJwk(jwk, headers, claims);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, String jwtLocation) {
        return signWithPrivateKey(privateKey, (String) null, jwtLocation);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, String keyId, String jwtLocation) {
        return signWithPrivateKey(privateKey, kidToMap(keyId), jwtLocation);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, Map<String, Object> headers, String jwtLocation) {
        return readClaimsAndSign(privateKey, headers, jwtLocation);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, Map<String, Object> claims) {
        return signWithPrivateKey(privateKey, (String) null, claims);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, String keyId, Map<String, Object> claims) {
        return signWithPrivateKey(privateKey, kidToMap(keyId), claims);
    }

    public static String signWithPrivateKey(PrivateKey privateKey, Map<String, Object> headers, Map<String, Object> claims) {
        return convertToClaimsAndSign(privateKey, headers, claims);
    }

    public static String signWithSecretKey(SecretKey secretKey, Map<String, Object> claims) {
        return signWithSecretKey(secretKey, (String) null, claims);
    }

    public static String signWithSecretKey(SecretKey secretKey, String keyId, Map<String, Object> claims) {
        return signWithSecretKey(secretKey, kidToMap(keyId), claims);
    }

    public static String signWithSecretKey(SecretKey secretKey, Map<String, Object> headers, Map<String, Object> claims) {
        return convertToClaimsAndSign(secretKey, headers, claims);
    }

    public static String signWithSecretKey(SecretKey secretKey, String jwtLocation) {
        return signWithSecretKey(secretKey, (String) null, jwtLocation);
    }

    public static String signWithSecretKey(SecretKey secretKey, String keyId, String jwtLocation) {
        return signWithSecretKey(secretKey, kidToMap(keyId), jwtLocation);
    }

    public static String signWithSecretKey(SecretKey secretKey, Map<String, Object> headers, String jwtLocation) {
        return readClaimsAndSign(secretKey, headers, jwtLocation);
    }

    public static String sign(Map<String, Object> claims) {
        return sign((String) null, claims);
    }

    public static String sign(String keyId, Map<String, Object> claims) {
        return sign(kidToMap(keyId), claims);
    }

    public static String sign(Map<String, Object> headers, Map<String, Object> claims) {
        return convertToClaimsAndSign(getSigningKeyFromConfig(), headers, claims);
    }

    static String readClaimsAndSign(Key signingKey, Map<String, Object> headers, String jwtLocation) {
        return signJwtClaimsInternal(signingKey, headers, parseJwtClaims(jwtLocation));
    }

    static String convertToClaimsAndSign(Key signingKey, Map<String, Object> headers, Map<String, Object> claimsMap) {
        return signJwtClaimsInternal(signingKey, headers, convertToClaims(claimsMap));
    }

    static String signJwtClaimsInternal(Key signingKey, Map<String, Object> headers, JwtClaims claims) {

        long currentTimeInSecs = currentTimeInSecs();
        if (!claims.hasClaim(Claims.iat.name())) {
            claims.setIssuedAt(NumericDate.fromSeconds(currentTimeInSecs));
        }
        if (!claims.hasClaim(Claims.exp.name())) {
            claims.setExpirationTime(NumericDate.fromSeconds(currentTimeInSecs() + 300));
        }
        if (!claims.hasClaim(Claims.jti.name())) {
            claims.setGeneratedJwtId();
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey);
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            jws.setHeader(entry.getKey(), entry.getValue());
        }
        if (!headers.containsKey("typ")) {
            jws.setHeader("typ", "JWT");
        }
        if (!headers.containsKey("alg")) {
            jws.setAlgorithmHeaderValue(keyAlgorithm(signingKey));
        }

        try {
            return jws.getCompactSerialization();
        } catch (Exception ex) {
            throw new JwtException("Failure to create a signed JWT token: " + ex, ex);
        }
    }

    static String readClaimsAndSignWithJwk(JsonWebKey jwk, Map<String, Object> headers, String jwtLocation) {
        return signjwtClaimsWithJwkInternal(jwk, headers, parseJwtClaims(jwtLocation));
    }

    static String convertToClaimsAndSignWithJwk(JsonWebKey jwk, Map<String, Object> headers, Map<String, Object> claims) {
        return signjwtClaimsWithJwkInternal(jwk, headers, convertToClaims(claims));
    }

    static String signjwtClaimsWithJwkInternal(JsonWebKey jwk, Map<String, Object> headers, JwtClaims claims) {
        Key key = jwk.getKey();
        if (key instanceof PrivateKey || key instanceof SecretKey) {

            Map<String, Object> newHeaders = new HashMap<>();
            newHeaders.putAll(headers);
            if (!newHeaders.containsKey("kid") && jwk.getKeyId() != null) {
                newHeaders.put("kid", jwk.getKeyId());
            }
            if (!newHeaders.containsKey("alg") && jwk.getAlgorithm() != null) {
                newHeaders.put("alg", jwk.getAlgorithm());
            }
            String alg = (String) newHeaders.get("alg");
            if (key instanceof SecretKey && !alg.startsWith("HS")
                    || key instanceof RSAPublicKey && !alg.startsWith("RS")
                    || key instanceof ECPublicKey && !alg.startsWith("ES")) {
                throw new IllegalArgumentException("JWK algorithm 'alg' value does not match a key type");
            }

            return signJwtClaimsInternal(key, newHeaders, claims);
        } else {
            throw new IllegalArgumentException("Only PrivateKey or SecretKey can be be used to sign a token");
        }
    }

    static String keyAlgorithm(Key signingKey) {
        if (signingKey instanceof RSAPrivateKey) {
            return AlgorithmIdentifiers.RSA_USING_SHA256;
        } else if (signingKey instanceof ECPrivateKey) {
            return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
        } else if (signingKey instanceof SecretKey) {
            return AlgorithmIdentifiers.HMAC_SHA256;
        } else {
            throw new IllegalArgumentException("Unsupported key algorithm: " + signingKey.getAlgorithm());
        }

    }

    static String readJsonContent(String jsonResName) {
        try {
            InputStream contentIS = JwtSigningUtils.class.getResourceAsStream(jsonResName);
            try (BufferedReader buffer = new BufferedReader(new InputStreamReader(contentIS))) {
                return buffer.lines().collect(Collectors.joining("\n"));
            }
        } catch (IOException ex) {
            throw new JwtException("Failure to read the json content:" + ex, ex);
        }
    }

    static JwtClaims convertToClaims(Map<String, Object> claimsMap) {
        JwtClaims claims = new JwtClaims();
        convertToClaims(claims, claimsMap);
        return claims;
    }

    static void convertToClaims(JwtClaims claims, Map<String, Object> claimsMap) {
        for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
            claims.setClaim(entry.getKey(), entry.getValue());
        }
    }

    /**
     * @return the current time in seconds since epoch
     */
    static int currentTimeInSecs() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    static JsonWebKey createJsonWebKey(String jwkString) {
        try {
            return JsonWebKey.Factory.newJwk(JsonUtil.parseJson(jwkString));
        } catch (Exception ex) {
            throw new JwtException("Failure to parse JWK:" + ex, ex);
        }
    }

    static JsonWebKey findJsonWebKeyInSet(String jwkSetString, String keyId) {
        JsonWebKeySet jwkSet = null;
        try {
            jwkSet = new JsonWebKeySet(jwkSetString);
        } catch (Exception ex) {
            throw new JwtException("Failure to parse JWK Set:" + ex, ex);
        }
        if (keyId == null) {
            if (jwkSet.getJsonWebKeys().size() == 1) {
                return jwkSet.getJsonWebKeys().get(0);
            } else {
                throw new IllegalArgumentException("Key id 'kid' header value must be provided");
            }
        }
        JsonWebKey jwk = jwkSet.findJsonWebKey(keyId, null, null, null);
        if (jwk == null) {
            throw new IllegalArgumentException("JWK set has no key with a key id 'kid' header '" + keyId + "'");
        }
        return jwk;
    }

    static Map<String, Object> kidToMap(String keyId) {
        return keyId == null ? Collections.emptyMap() : Collections.<String, Object> singletonMap("kid", keyId);
    }

    static Key getSigningKeyFromConfig() {
        try {
            String keyLocation = ConfigProvider.getConfig().getValue("smallrye.jwt.sign.private-key-location", String.class);
            try {
                return KeyUtils.readPrivateKey(keyLocation);
            } catch (Exception ex) {
                throw new IllegalArgumentException("PEM key can not be loaded from: " + keyLocation);
                // TODO: try JWK(S) as well
            }
        } catch (NoSuchElementException ex) {
            throw new IllegalArgumentException("Please set a 'smallrye.jwt.sign.private-key-location' property");
        }
    }

    static JwtClaims parseJwtClaims(String jwtLocation) {
        try {
            return JwtClaims.parse(readJsonContent(jwtLocation));
        } catch (Exception ex) {
            throw new JwtException("Failure to parse the JWT claims:" + ex, ex);
        }
    }

    static Key readPrivatePemKey(String pemKeyLocation) {
        try {
            return KeyUtils.readPrivateKey(pemKeyLocation);
        } catch (Exception ex) {
            throw new JwtException("Failure to read the private key:" + ex, ex);
        }
    }

}
