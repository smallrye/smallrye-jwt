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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.eclipse.microprofile.jwt.Claims;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public class SmallryeJwtUtils {
    private static final Integer MAX_PATH_DEPTH = 4;
    private static final String COOKIE_HEADER = "Cookie";

    private SmallryeJwtUtils() {
    }

    public static void setContextSubPath(JWTAuthContextInfo contextInfo, Optional<String> subPath) {
        if (checkClaimPath(Claims.sub.name(), subPath)) {
            contextInfo.setSubjectPath(subPath.get());
        }
    }

    public static void setContextGroupsPath(JWTAuthContextInfo contextInfo, Optional<String> groupsPath) {
        if (checkClaimPath(Claims.groups.name(), groupsPath)) {
            contextInfo.setGroupsPath(groupsPath.get());
        }
    }

    private static boolean checkClaimPath(String claimName, Optional<String> claimPath) {
        if (claimPath.isPresent()) {
            final String[] pathSegments = claimPath.get().split("/");
            if (MAX_PATH_DEPTH < pathSegments.length) {
                JWTLogging.log.maximumPathDepthReached(claimName, pathSegments.length, MAX_PATH_DEPTH);
            } else {
                return true;
            }
        }
        return false;
    }

    public static void setContextTokenCookie(JWTAuthContextInfo contextInfo, Optional<String> cookieName) {
        if (COOKIE_HEADER.equals(contextInfo.getTokenHeader())) {
            if (cookieName.isPresent()) {
                contextInfo.setTokenCookie(cookieName.get());
            }
        }
    }

    public static void setTokenSchemes(JWTAuthContextInfo contextInfo, Optional<String> tokenSchemes) {
        if (tokenSchemes.isPresent()) {
            final List<String> schemes = new ArrayList<>();
            for (final String s : tokenSchemes.get().split(",")) {
                schemes.add(s.trim());
            }
            contextInfo.setTokenSchemes(schemes);
        }
    }
}
