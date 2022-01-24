/**
 * 
 */
package org.folio.sso.saml.metadata;

import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.saml.metadata.SAML2MetadataResolver;
import org.pac4j.saml.state.SAML2StateGenerator;
import org.pac4j.saml.util.Configuration;

import io.vertx.core.json.JsonObject;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * @author Steve Osguthorpe
 *
 */
public class RequestScopedMetadataResolver implements SAML2MetadataResolver {

  private static final Logger log = LogManager.getLogger(RequestScopedMetadataResolver.class);
  private final SAML2MetadataResolver fullMetadata;
  private final EntityDescriptor entityDescriptor;
  
  public RequestScopedMetadataResolver(final SAML2MetadataResolver fullIpdMetaResolver, final WebContext webContext, final SessionStore sessionStore) {
    this.fullMetadata = fullIpdMetaResolver;
    
    Optional<Object> idpId = sessionStore != null ? sessionStore.get(webContext, SAML2StateGenerator.SAML_RELAY_STATE_ATTRIBUTE) : Optional.empty();
    
    // RelayState could contain idp to use.
    String requestIdpId = idpId
      .map((val) -> {
        final String valStr = (String)val;
        final JsonObject relayStateFromSession = new JsonObject( valStr );
        return relayStateFromSession.getString("entityID");
      })
      
      .orElseGet(() -> {
        return webContext.getRequestParameter("RelayState")
          .map((val) -> {
            final JsonObject relayStateFromRequest = new JsonObject( val );
            return relayStateFromRequest.getString("entityID");
          })
            
          .orElseGet(() -> {
            return webContext.getRequestParameter("entityID").orElse(null);
          });
      });

    try {
      if (requestIdpId == null && (fullMetadata instanceof FederationIdentityProviderMetadataResolver)) {
        FederationIdentityProviderMetadataResolver fedRes = (FederationIdentityProviderMetadataResolver) fullMetadata;
        if (fedRes.hasMultipleIdpsConfigure()) {
          throw new AmbiguousTargetIDPException("Metadata cannot be retrieved because entityID is null, and more that 1 IDP configured");
          
        } else {
          log.debug("Allowing entityId to be ommitted when only 1 IDP is configured for backwards compatibility");
          requestIdpId = fedRes.getEntityId();
        }
      }
      
      entityDescriptor = fullMetadata.resolve().resolveSingle(new CriteriaSet(new EntityIdCriterion(requestIdpId)));
      if (entityDescriptor == null) throw new TechnicalException("Metadata cannot be retrieved because entityID could not be matched against known IDP entities");
    } catch (ResolverException e) {
      throw new AmbiguousTargetIDPException("Metadata cannot be retrieved because entityID could not be matched against known IDP entities", e);
    }
    
    log.debug("Resolved IDP Entity from with ID: " + getEntityId());
  }

  @Override
  public MetadataResolver resolve () {
    return fullMetadata.resolve();
  }
  
  @Override
  public MetadataResolver resolve (boolean force) {
    return fullMetadata.resolve(force);
  }

  @Override
  public String getEntityId () {
    return entityDescriptor.getEntityID();
  }

  @Override
  public String getMetadata() {
    return Configuration.serializeSamlObject(getEntityDescriptorElement()).toString();
  }

  @Override
  public XMLObject getEntityDescriptorElement () {
    return entityDescriptor;
  }

}
