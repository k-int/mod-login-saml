package org.folio.sso.saml.metadata;

import io.vertx.core.VertxException;

/**
 * @author Steve Osguthorpe
 */
public class AmbiguousTargetIDPException extends VertxException {
  private static final long serialVersionUID = 8273817862353852125L;

  public AmbiguousTargetIDPException (String message) {
    super(message);
  }
  public AmbiguousTargetIDPException (String message, Throwable cause) {
    super(message, cause);
  }
}
