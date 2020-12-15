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
package io.smallrye.jwt.build;

import java.security.Security;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.BouncyCastleProviderHelp;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
// import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.util.KeyUtils;

public class JwtSignPS256Test {
    @BeforeClass
    public static void installBouncyCastleProviderIfNeeded() {
        if (!isPS256Supported()) {
            BouncyCastleProviderHelp.enableBouncyCastleProvider();
        }
    }

    @AfterClass
    public static void uninstallBouncyCastleProviderIfNeeded() {
        if (!isPS256Supported()) {
            Security.removeProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
        }
    }

    private static boolean isPS256Supported() {
        for (String sigAlg : Security.getAlgorithms("Signature")) {
            if ("RSASSA-PSS".equalsIgnoreCase(sigAlg)) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void testSignClaimsPS256() throws Exception {
        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jws().algorithm(SignatureAlgorithm.PS256)
                .sign("/privateKey.pem");

        JsonWebSignature jws = JwtSignTest.getVerifiedJws(jwt, KeyUtils.readPublicKey("/publicKey.pem"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        JwtSignTest.checkDefaultClaimsAndHeaders(JwtSignTest.getJwsHeaders(jwt, 2), claims, "PS256", 300);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

}
