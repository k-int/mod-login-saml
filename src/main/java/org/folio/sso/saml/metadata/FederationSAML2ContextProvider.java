package org.folio.sso.saml.metadata;

import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.context.SAML2ContextProvider;
import org.pac4j.saml.context.SAML2MessageContext;
import org.pac4j.saml.metadata.SAML2MetadataResolver;
import org.pac4j.saml.store.SAMLMessageStoreFactory;

/**
 * Context provider that builds the current context using the supplied WebContext to provide the desired IDP provider.
 * 
 * @author Steve Osguthorpe
 */
public class FederationSAML2ContextProvider extends SAML2ContextProvider {

  /**
   * @see SAML2ContextProvider#SAML2ContextProvider(SAML2MetadataResolver, SAML2MetadataResolver, SAMLMessageStoreFactory))
   */
  public FederationSAML2ContextProvider (SAML2MetadataResolver idpEntityId,
      SAML2MetadataResolver spEntityId,
      SAMLMessageStoreFactory samlMessageStoreFactory) {
    super(idpEntityId, spEntityId, samlMessageStoreFactory);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public SAML2MessageContext buildContext(final SAML2Client client, final WebContext webContext, final SessionStore sessionStore) {
    final SAML2MessageContext context = buildServiceProviderContext(client, webContext, sessionStore); // Unchanged SP context.
    //      addIDPContext(context);
    // We need to provide a chaining IDP config.        
    addFederationAwareIDPContext(client.getIdentityProviderMetadataResolver(), context, webContext);
    context.setWebContext(webContext);
    context.setSessionStore(sessionStore);
    return context;
  }

  
  /**
   * Use the web context to select an IDP from the federation.
   * 
   * @param context
   * @param webContext
   */
  protected void addFederationAwareIDPContext(final SAML2MetadataResolver allIdps, final SAML2MessageContext context, final WebContext webContext) {
    final SessionStore sessionStore = context.getSessionStore();
    
    // We create a scoped MD resolver that resolves to Entity based on the entity ID in the request.
    final SAML2MetadataResolver mdResolver = new RequestScopedMetadataResolver(allIdps, webContext, sessionStore);
    
    final SAMLPeerEntityContext peerContext = context.getSAMLPeerEntityContext();
    
    peerContext.setEntityId(mdResolver.getEntityId());
    peerContext.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    addContext(mdResolver, peerContext, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
  }

}

