package io.smallrye.jwt.tck;

import io.smallrye.jwt.auth.cdi.SmallRyeJWTAuthCDIExtension;

public class OptionalAwareSmallRyeJWTAuthCDIExtension extends SmallRyeJWTAuthCDIExtension {
    // TODO - radcortez - This should be changed in the original extension. This is how Elytron is doing it.
    // Maybe because difference between 1.0 and 1.1? Right now it doesn't make sense to keeo it as is, since it will fail the TCK.
    @Override
    protected boolean registerOptionalClaimTypeProducer() {
        return true;
    }
}
