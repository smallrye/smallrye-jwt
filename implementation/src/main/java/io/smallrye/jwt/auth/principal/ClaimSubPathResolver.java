package io.smallrye.jwt.auth.principal;

import java.util.Map;

import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;

class ClaimSubPathResolver {
    private static Logger logger = Logger.getLogger(ClaimSubPathResolver.class);

    private ClaimSubPathResolver() {
    }

    static String checkSubPath(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getSubPath() != null) {
            final String[] pathSegments = authContextInfo.getSubPath().split("/");
            return findSub(authContextInfo, claimsSet.getClaimsMap(), pathSegments, 0);
        }
        return null;
    }

    static String findSub(
            JWTAuthContextInfo authContextInfo,
            Map<String, Object> claimsMap,
            String[] pathArray,
            int step) {
        Object claimValue = claimsMap.get(pathArray[step]);
        if (claimValue == null) {
            logger.warnf("No claim exists at the path %s at segment %s",
                    authContextInfo.getGroupsPath(), pathArray[step]);
        } else if (step + 1 < pathArray.length) {
            if (claimValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nextMap = (Map<String, Object>) claimValue;
                int nextStep = step + 1;
                return findSub(authContextInfo, nextMap, pathArray, nextStep);
            } else {
                logger.warnf("Claim value at the path %s is not a json object", authContextInfo.getGroupsPath());
            }
        } else if (claimValue instanceof String) {
            // last segment
            try {
                return (String) claimValue;
            } catch (ClassCastException e) {
                logger.warnf("Claim value at the path %s is not an array of strings", authContextInfo.getGroupsPath());
            }
        } else {
            // last segment
            logger.warnf("Claim value at the path %s is not an array", authContextInfo.getGroupsPath());
        }
        return null;
    }
}
