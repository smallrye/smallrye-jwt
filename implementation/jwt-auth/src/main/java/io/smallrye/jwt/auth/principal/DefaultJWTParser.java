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
package io.smallrye.jwt.auth.principal;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.Set;

import javax.crypto.SecretKey;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.cdi.JWTCallerPrincipalFactoryProducer;
import io.smallrye.jwt.util.KeyUtils;

/**
 * A default implementation of {@link JWTParser}.
 */
@ApplicationScoped
public class DefaultJWTParser implements JWTParser {

    private static final String ED_EC_PUBLIC_KEY_INTERFACE = "java.security.interfaces.EdECPublicKey";
    private static final String XEC_PRIVATE_KEY_INTERFACE = "java.security.interfaces.XECPrivateKey";

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private JWTCallerPrincipalFactory callerPrincipalFactory;

    public DefaultJWTParser() {
    }

    public DefaultJWTParser(JWTAuthContextInfo authContextInfo) {
        this(authContextInfo, new JWTCallerPrincipalFactoryProducer().getFactory());
    }

    public DefaultJWTParser(JWTCallerPrincipalFactory factory) {
        this(null, factory);
    }

    public DefaultJWTParser(JWTAuthContextInfo authContextInfo, JWTCallerPrincipalFactory factory) {
        this.authContextInfo = authContextInfo;
        this.callerPrincipalFactory = factory;
    }

    public JsonWebToken parse(final String bearerToken) throws ParseException {
        return getCallerPrincipalFactory().parse(bearerToken, authContextInfo);
    }

    @Override
    public JsonWebToken parse(String bearerToken, JWTAuthContextInfo newAuthContextInfo) throws ParseException {
        JWTCallerPrincipalFactory factory = getCallerPrincipalFactory();
        if (newAuthContextInfo.getPublicKeyLocation() != null || newAuthContextInfo.getPublicKeyContent() != null
                || newAuthContextInfo.getDecryptionKeyContent() != null
                || newAuthContextInfo.getDecryptionKeyLocation() != null) {
            // in these cases a `KeyLocationResolver` is cached
            try {
                factory = factory.getClass().getDeclaredConstructor().newInstance();
            } catch (Throwable t) {
                PrincipalMessages.msg.newJWTCallerPrincipalFactoryFailure(t);
            }
        }

        return factory.parse(bearerToken, newAuthContextInfo);
    }

    @Override
    public JsonWebToken verify(String bearerToken, PublicKey key) throws ParseException {
        JWTAuthContextInfo newAuthContextInfo = copyAuthContextInfo();
        newAuthContextInfo.setPublicVerificationKey(key);
        if (key instanceof ECPublicKey) {
            setSignatureAlgorithmIfNeeded(newAuthContextInfo, "ES", SignatureAlgorithm.ES256);
        } else if (isEdECPublicKey(key)) {
            setSignatureAlgorithmIfNeeded(newAuthContextInfo, "EdDSA", SignatureAlgorithm.EDDSA);
        } else {
            setSignatureAlgorithmIfNeeded(newAuthContextInfo, "RS", SignatureAlgorithm.RS256);
        }
        return getCallerPrincipalFactory().parse(bearerToken, newAuthContextInfo);
    }

    @Override
    public JsonWebToken verify(String bearerToken, SecretKey key) throws ParseException {
        JWTAuthContextInfo newAuthContextInfo = copyAuthContextInfo();
        newAuthContextInfo.setSecretVerificationKey(key);
        setSignatureAlgorithmIfNeeded(newAuthContextInfo, "HS", SignatureAlgorithm.HS256);
        return getCallerPrincipalFactory().parse(bearerToken, newAuthContextInfo);
    }

    @Override
    public JsonWebToken verify(String bearerToken, String secret) throws ParseException {
        return verify(bearerToken, KeyUtils.createSecretKeyFromSecret(secret));
    }

    @Override
    public JsonWebToken decrypt(String bearerToken, PrivateKey key) throws ParseException {
        JWTAuthContextInfo newAuthContextInfo = copyAuthContextInfo();
        newAuthContextInfo.setPrivateDecryptionKey(key);
        if (key instanceof ECPrivateKey || isXecPrivateKey(key)) {
            setKeyEncryptionAlgorithmIfNeeded(newAuthContextInfo, "EC", KeyEncryptionAlgorithm.ECDH_ES_A256KW);
        } else {
            setKeyEncryptionAlgorithmIfNeeded(newAuthContextInfo, "RS", KeyEncryptionAlgorithm.RSA_OAEP);
        }
        return getCallerPrincipalFactory().parse(bearerToken, newAuthContextInfo);
    }

    @Override
    public JsonWebToken decrypt(String bearerToken, SecretKey key) throws ParseException {
        JWTAuthContextInfo newAuthContextInfo = copyAuthContextInfo();
        newAuthContextInfo.setSecretDecryptionKey(key);
        setKeyEncryptionAlgorithmIfNeeded(newAuthContextInfo, "A256KW", KeyEncryptionAlgorithm.A256KW);
        return getCallerPrincipalFactory().parse(bearerToken, newAuthContextInfo);
    }

    @Override
    public JsonWebToken decrypt(String bearerToken, String secret) throws ParseException {
        return decrypt(bearerToken, KeyUtils.createSecretKeyFromSecret(secret));
    }

    private JWTCallerPrincipalFactory getCallerPrincipalFactory() {
        if (callerPrincipalFactory == null) {
            return JWTCallerPrincipalFactory.instance();
        }
        return callerPrincipalFactory;
    }

    private JWTAuthContextInfo copyAuthContextInfo() {
        return authContextInfo != null ? new JWTAuthContextInfo(authContextInfo) : new JWTAuthContextInfo();
    }

    private void setSignatureAlgorithmIfNeeded(JWTAuthContextInfo newAuthContextInfo, String algoStart,
            SignatureAlgorithm newAlgo) {
        SignatureAlgorithm algo = newAuthContextInfo.getSignatureAlgorithm();
        if (algo == null || !algo.getAlgorithm().startsWith(algoStart)) {
            newAuthContextInfo.setSignatureAlgorithm(newAlgo);
        }
    }

    private void setKeyEncryptionAlgorithmIfNeeded(JWTAuthContextInfo newAuthContextInfo, String algoStart,
            KeyEncryptionAlgorithm newAlgo) {
        Set<KeyEncryptionAlgorithm> algo = newAuthContextInfo.getKeyEncryptionAlgorithm();
        if (algo == null ||
                !algo.stream().anyMatch(s -> s.getAlgorithm().startsWith(algoStart))) {
            newAuthContextInfo.setKeyEncryptionAlgorithm(Collections.singleton(newAlgo));
        }
    }

    private static boolean isEdECPublicKey(Key verificationKey) {
        return KeyUtils.isSupportedKey(verificationKey, ED_EC_PUBLIC_KEY_INTERFACE);
    }

    private static boolean isXecPrivateKey(Key encKey) {
        return KeyUtils.isSupportedKey(encKey, XEC_PRIVATE_KEY_INTERFACE);
    }
}
