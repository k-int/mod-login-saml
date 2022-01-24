package org.folio.sso.saml;

import org.folio.sso.saml.metadata.FederationIdentityProviderMetadataResolver;
import org.folio.sso.saml.metadata.FederationSAML2ContextProvider;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExtendedSamlClient extends SAML2Client {
  protected final Logger log = LoggerFactory.getLogger(ExtendedSamlClient.class);

  public ExtendedSamlClient (SAML2Configuration configuration) {
    super(configuration);
  }
    
  @Override
  protected void initSAMLContextProvider() {
    // Build the contextProvider
    this.contextProvider = new FederationSAML2ContextProvider(
        this.idpMetadataResolver,
        this.spMetadataResolver,
        this.configuration.getSamlMessageStoreFactory());
  }

  @Override
  protected void initIdentityProviderMetadataResolver() {
    FederationIdentityProviderMetadataResolver md = new FederationIdentityProviderMetadataResolver(
        this.configuration,
        getName()
        );
    this.idpMetadataResolver = md;
    md.init();
  }
}
