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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.jboss.logging.Logger;
import org.jose4j.jws.AlgorithmIdentifiers;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public class SmallryeJwtUtils {
    private static final Integer MAX_PATH_DEPTH = 4;
    private static final String COOKIE_HEADER = "Cookie";
    private static final Set<String> SUPPORTED_ALGORITHMS = new HashSet<>(Arrays.asList(AlgorithmIdentifiers.RSA_USING_SHA256,
            AlgorithmIdentifiers.RSA_USING_SHA384,
            AlgorithmIdentifiers.RSA_USING_SHA512,
            AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
            AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
            AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512));

    private static final Logger log = Logger.getLogger(SmallryeJwtUtils.class);

    private SmallryeJwtUtils() {
    }

    public static void setContextSubPath(JWTAuthContextInfo contextInfo, Optional<String> subPath) {
        if (subPath != null && subPath.isPresent()) {
            final String[] pathSegments = subPath.get().split("/");
            if (MAX_PATH_DEPTH < pathSegments.length) {
                log.errorf("Sub path configuration will be ignored because its depth is too large:"
                        + " %d, maximum depth is %d.", pathSegments.length, MAX_PATH_DEPTH);
            } else {
                contextInfo.setSubPath(subPath.get());
            }
        }
    }

    public static void setContextGroupsPath(JWTAuthContextInfo contextInfo, Optional<String> groupsPath) {
        if (groupsPath != null && groupsPath.isPresent()) {
            final String[] pathSegments = groupsPath.get().split("/");
            if (MAX_PATH_DEPTH < pathSegments.length) {
                log.errorf("Groups path configuration will be ignored because its depth is too large:"
                        + " %d, maximum depth is %d.", pathSegments.length, MAX_PATH_DEPTH);
            } else {
                contextInfo.setGroupsPath(groupsPath.get());
            }
        }
    }

    public static void setContextTokenCookie(JWTAuthContextInfo contextInfo, Optional<String> cookieName) {
        if (cookieName != null && cookieName.isPresent()) {
            if (!COOKIE_HEADER.equals(contextInfo.getTokenHeader())) {
                log.error("Token header is not 'Cookie', the cookie name value will be ignored");
            } else {
                contextInfo.setTokenCookie(cookieName.get());
            }
        }
    }

    public static void setWhitelistAlgorithms(JWTAuthContextInfo contextInfo, List<String> whitelistAlgorithms) {
        if (whitelistAlgorithms != null && !whitelistAlgorithms.isEmpty()) {
            for (String whitelistAlgorithm : whitelistAlgorithms) {
                if (SUPPORTED_ALGORITHMS.contains(whitelistAlgorithm)) {
                    contextInfo.getWhitelistAlgorithms().add(whitelistAlgorithm);
                } else {
                    log.errorf("Algorithm %s not supported", whitelistAlgorithm);
                }
            }
        }
    }
}
