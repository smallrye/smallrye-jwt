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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

/**
 * VerificationKeyResolver which checks the MP-JWT 1.1 mp.jwt.verify.publickey and mp.jwt.verify.publickey.location
 * configuration properties to resolve a verification key.
 */
public class KeyLocationResolver extends AbstractKeyLocationResolver implements VerificationKeyResolver {

    public KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        super(authContextInfo);

        try {
            initializeKeyContent();
        } catch (Exception e) {
            reportLoadKeyException(authContextInfo.getPublicKeyContent(), authContextInfo.getPublicKeyLocation(), e);
        }
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        verifyKid(jws, authContextInfo.getTokenKeyId());

        // The verificationKey may have been calculated in the constructor from the local PEM, or,
        // if authContextInfo.getTokenKeyId() is not null - from the local JWK(S) content.
        if (key != null) {
            return key;
        }

        // At this point the key can be loaded from either the HTTPS or local JWK(s) content using
        // the current token kid to select the key.
        Key theKey = tryAsVerificationJwk(jws);

        if (theKey == null) {
            reportUnresolvableKeyException(authContextInfo.getPublicKeyContent(), authContextInfo.getPublicKeyLocation());
        }
        return theKey;
    }

    private Key tryAsVerificationJwk(JsonWebSignature jws) throws UnresolvableKeyException {
        JsonWebKey jwk = super.tryAsJwk(jws, authContextInfo.getSignatureAlgorithm().getAlgorithm());
        return fromJwkToVerificationKey(jwk);
    }

    private Key fromJwkToVerificationKey(JsonWebKey jwk) {
        Key theKey = null;
        if (jwk != null) {
            theKey = getSecretKeyFromJwk(jwk);
            if (theKey == null) {
                theKey = PublicJsonWebKey.class.cast(jwk).getPublicKey();
            }
        }
        return theKey;
    }

    protected void initializeKeyContent() throws Exception {

        if (isHttpsJwksInitialized(authContextInfo.getPublicKeyLocation())) {
            return;
        }

        String content = authContextInfo.getPublicKeyContent() != null
                ? authContextInfo.getPublicKeyContent()
                : readKeyContent(authContextInfo.getPublicKeyLocation());

        // Try to init the verification key from the local PEM or JWK(S) content
        if (mayBeFormat(KeyFormat.PEM_KEY)) {
            key = tryAsPEMPublicKey(content, authContextInfo.getSignatureAlgorithm());
            if (key != null || isFormat(KeyFormat.PEM_KEY)) {
                return;
            }
        }
        if (mayBeFormat(KeyFormat.PEM_CERTIFICATE)) {
            key = tryAsPEMCertificate(content);
            if (key != null || isFormat(KeyFormat.PEM_CERTIFICATE)) {
                return;
            }
        }
        JsonWebKey jwk = loadFromJwk(content, authContextInfo.getTokenKeyId(),
                authContextInfo.getSignatureAlgorithm().getAlgorithm());
        key = fromJwkToVerificationKey(jwk);
    }

    static PublicKey tryAsPEMPublicKey(String content, SignatureAlgorithm algo) {
        PrincipalLogging.log.checkKeyContentIsBase64EncodedPEMKey();
        PublicKey key = null;
        try {
            key = KeyUtils.decodePublicKey(content, algo);
            PrincipalLogging.log.keyCreatedFromEncodedPEMKey();
        } catch (Exception e) {
            PrincipalLogging.log.keyContentIsNotValidEncodedPEMKey(e);
        }
        return key;
    }

    PublicKey tryAsPEMCertificate(String content) {
        X509Certificate cert = super.loadPEMCertificate(content);
        return cert == null ? null : cert.getPublicKey();
    }
}
