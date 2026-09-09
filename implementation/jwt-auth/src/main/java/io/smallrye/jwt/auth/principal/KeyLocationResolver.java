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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.JwsHeaders;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.auth.VerificationKeyResolver;
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
    public Key resolveKey(JsonWebSignature jws) throws UnresolvableKeyException {
        JwsHeaders headers = jws.headers();
        String kid = headers.keyId();
        String tokenAlg = headers.algorithm();
        verifyKid(kid, authContextInfo.getTokenKeyId());

        // The verificationKey may have been calculated in the constructor from the local PEM, or,
        // if authContextInfo.getTokenKeyId() is not null - from the local JWK(S) content.
        if (key != null) {
            return key;
        }

        // At this point the key can be loaded from either the HTTPS or local JWK(s) content using
        // the current token kid to select the key.
        Key theKey = tryAsVerificationJwk(kid, tokenAlg);

        if (theKey == null) {
            if (remoteJwkSet != null && kid != null) {
                throw PrincipalMessages.msg.unmatchedTokenKidException();
            }
            reportUnresolvableKeyException(authContextInfo.getPublicKeyContent(), authContextInfo.getPublicKeyLocation());
        }
        return theKey;
    }

    private Key tryAsVerificationJwk(String kid, String tokenAlg) throws UnresolvableKeyException {

        for (SignatureAlgorithm sigAlg : authContextInfo.getSignatureAlgorithm()) {
            if (sigAlg.getAlgorithm().equals(tokenAlg)) {
                JWK jwk = super.tryAsJwk(kid, sigAlg.getAlgorithm());
                if (jwk != null) {
                    return fromJwkToVerificationKey(jwk);
                }
            }
        }
        return null;
    }

    private Key fromJwkToVerificationKey(JWK jwk) {
        Key theKey = null;
        if (jwk != null) {
            theKey = getSecretKeyFromJwk(jwk);
            if (theKey == null) {
                try {
                    theKey = ((AsymmetricJWK) jwk).toPublicKey();
                } catch (JOSEException e) {
                    PrincipalLogging.log.failedToCreateKeyFromJWKS(e);
                }
            }
        }
        return theKey;
    }

    protected void initializeKeyContent() throws Exception {

        if (initializeHttpsJwks(authContextInfo.getPublicKeyLocation())) {
            return;
        }

        String content = null;
        if (authContextInfo.getPublicKeyContent() != null) {
            content = authContextInfo.getPublicKeyContent();
        } else if (authContextInfo.getSecretKeyContent() != null) {
            content = authContextInfo.getSecretKeyContent();
        } else {
            content = readKeyContent(authContextInfo.getPublicKeyLocation());
        }

        // Try to init the verification key from the local PEM or JWK(S) content
        if (mayBeFormat(KeyFormat.PEM_KEY)) {
            key = tryAsPEMPublicKey(content, authContextInfo.getSignatureAlgorithm().iterator().next());
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
        if (authContextInfo.getSignatureAlgorithm().size() == 1) {
            JWK jwk = loadFromJwk(content, authContextInfo.getTokenKeyId(),
                    authContextInfo.getSignatureAlgorithm().iterator().next().getAlgorithm());
            if (jwk != null) {
                key = fromJwkToVerificationKey(jwk);
            }
        } else {
            super.loadJWKContent(content);
        }
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
