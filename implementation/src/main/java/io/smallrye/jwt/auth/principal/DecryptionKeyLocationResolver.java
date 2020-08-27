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
import java.util.List;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.KeyUtils;

/**
 * DecryptionKeyResolver which checks the MP-JWT 1.1 mp.jwt.decrypt.key.location configuration
 * property to resolve a decryption key.
 */
public class DecryptionKeyLocationResolver extends AbstractKeyLocationResolver implements DecryptionKeyResolver {

    public DecryptionKeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        super(authContextInfo);
        try {
            initializeKeyContent();
        } catch (Exception e) {
            reportLoadKeyException(authContextInfo.getDecryptionKeyContent(), authContextInfo.getDecryptionKeyLocation(), e);
        }
    }

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext)
            throws UnresolvableKeyException {
        verifyKid(jwe, authContextInfo.getTokenDecryptionKeyId());

        // The key may have been calculated in the constructor from the local PEM, or,
        // if authContextInfo.getTokenKeyId() is not null - from the local JWK(S) content.
        if (key != null) {
            return key;
        }

        // At this point the key can be loaded from either the HTTPS or local JWK(s) content using
        // the current token kid to select the key.
        Key theKey = tryAsDecryptionJwk(jwe);

        if (theKey == null) {
            reportUnresolvableKeyException(authContextInfo.getDecryptionKeyContent(),
                    authContextInfo.getDecryptionKeyLocation());
        }
        return theKey;
    }

    private Key tryAsDecryptionJwk(JsonWebEncryption jwe) throws UnresolvableKeyException {
        JsonWebKey jwk = super.tryAsJwk(jwe, authContextInfo.getKeyEncryptionAlgorithm().getAlgorithm());
        return fromJwkToDecryptionKey(jwk);
    }

    private Key fromJwkToDecryptionKey(JsonWebKey jwk) {
        Key theKey = null;
        if (jwk != null) {
            theKey = getSecretKeyFromJwk(jwk);
            if (theKey == null) {
                theKey = PublicJsonWebKey.class.cast(jwk).getPrivateKey();
            }
        }
        return theKey;
    }

    protected void initializeKeyContent() throws Exception {

        if (isHttpsJwksInitialized(authContextInfo.getDecryptionKeyLocation())) {
            return;
        }

        String content = authContextInfo.getDecryptionKeyContent() != null
                ? authContextInfo.getDecryptionKeyContent()
                : readKeyContent(authContextInfo.getDecryptionKeyLocation());

        // Try to init the verification key from the local PEM or JWK(S) content
        if (mayBeFormat(KeyFormat.PEM_KEY)) {
            key = tryAsPEMPrivateKey(content);
            if (key != null || isFormat(KeyFormat.PEM_KEY)) {
                return;
            }
        }
        JsonWebKey jwk = loadFromJwk(content, authContextInfo.getTokenDecryptionKeyId(),
                authContextInfo.getKeyEncryptionAlgorithm().getAlgorithm());
        key = fromJwkToDecryptionKey(jwk);
    }

    static PrivateKey tryAsPEMPrivateKey(String content) {
        PrincipalLogging.log.checkKeyContentIsBase64EncodedPEMKey();
        PrivateKey key = null;
        try {
            key = KeyUtils.decodeDecryptionPrivateKey(content);
            PrincipalLogging.log.keyCreatedFromEncodedPEMKey();
        } catch (Exception e) {
            PrincipalLogging.log.keyContentIsNotValidEncodedPEMKey(e);
        }
        return key;
    }
}
