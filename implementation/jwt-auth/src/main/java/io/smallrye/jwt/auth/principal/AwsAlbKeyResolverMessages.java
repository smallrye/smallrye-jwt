package io.smallrye.jwt.auth.principal;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;
import org.jose4j.lang.UnresolvableKeyException;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface AwsAlbKeyResolverMessages {
    AwsAlbKeyResolverMessages msg = Messages.getBundle(AwsAlbKeyResolverMessages.class);

    @Message(id = 14001, value = "Key is resolved from kid. Key location is not allowed. Provide only the path like: https://public-keys.auth.elb.[REGION].amazonaws.com")
    UnresolvableKeyException subPathNotAllowed();

}
