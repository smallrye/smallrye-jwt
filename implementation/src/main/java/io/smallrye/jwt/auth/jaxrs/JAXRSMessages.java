package io.smallrye.jwt.auth.jaxrs;

import java.lang.annotation.Annotation;
import java.util.Collection;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;
import org.jboss.logging.annotations.Transform;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface JAXRSMessages {
    JAXRSMessages msg = Messages.getBundle(JAXRSMessages.class);

    @Message(id = 9000, value = "Duplicate MicroProfile JWT annotations found on %s. Expected at most 1 annotation, found: %d")
    IllegalStateException duplicateJWTAnnotationsFound(String annotationPlacementDescriptor,
            @Transform(Transform.TransformType.SIZE) Collection<Annotation> annotations);
}
