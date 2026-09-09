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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.auth.DecryptionKeyResolver;
import io.smallrye.jwt.auth.JsonWebEncryption;
import io.smallrye.jwt.auth.JweHeaders;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.KeyUtils;

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
    public Key resolveKey(JsonWebEncryption jwe) throws UnresolvableKeyException {
        JweHeaders headers = jwe.headers();
        String kid = headers.keyId();
        String tokenAlg = headers.algorithm();
        verifyKid(kid, authContextInfo.getTokenDecryptionKeyId());

        // The key may have been calculated in the constructor from the local PEM, or,
        // if authContextInfo.getTokenKeyId() is not null - from the local JWK(S) content.
        if (key != null) {
            return key;
        }

        // At this point the key can be loaded from either the HTTPS or local JWK(s) content using
        // the current token kid to select the key.
        Key theKey = tryAsDecryptionJwk(kid, tokenAlg);

        if (theKey == null) {
            reportUnresolvableKeyException(authContextInfo.getDecryptionKeyContent(),
                    authContextInfo.getDecryptionKeyLocation());
        }
        return theKey;
    }

    private Key tryAsDecryptionJwk(String kid, String tokenAlg) throws UnresolvableKeyException {
        for (KeyEncryptionAlgorithm algo : authContextInfo.getKeyEncryptionAlgorithm()) {
            JWK jwk = super.tryAsJwk(kid, algo.getAlgorithm());
            if (jwk != null) {
                return fromJwkToDecryptionKey(jwk);
            }
        }
        return null;
    }

    private Key fromJwkToDecryptionKey(JWK jwk) {
        Key theKey = null;
        if (jwk != null) {
            theKey = getSecretKeyFromJwk(jwk);
            if (theKey == null) {
                try {
                    theKey = ((AsymmetricJWK) jwk).toPrivateKey();
                } catch (JOSEException e) {
                    PrincipalLogging.log.failedToCreateKeyFromJWKS(e);
                }
            }
        }
        return theKey;
    }

    protected void initializeKeyContent() throws Exception {

        if (initializeHttpsJwks(authContextInfo.getDecryptionKeyLocation())) {
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
        for (KeyEncryptionAlgorithm keyAlgo : authContextInfo.getKeyEncryptionAlgorithm()) {
            JWK jwk = loadFromJwk(content, authContextInfo.getTokenDecryptionKeyId(),
                    keyAlgo.getAlgorithm());
            if (jwk != null) {
                key = fromJwkToDecryptionKey(jwk);
            }
        }
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
