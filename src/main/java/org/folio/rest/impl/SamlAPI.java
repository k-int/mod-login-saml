package org.folio.rest.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.folio.config.ConfigurationsClient;
import org.folio.config.SamlClientLoader;
import org.folio.config.SamlConfigHolder;
import org.folio.config.model.SamlClientComposite;
import org.folio.config.model.SamlConfiguration;
import org.folio.rest.jaxrs.model.SamlCheck;
import org.folio.rest.jaxrs.model.SamlConfig;
import org.folio.rest.jaxrs.model.SamlConfigRequest;
import org.folio.rest.jaxrs.model.SamlLogin;
import org.folio.rest.jaxrs.model.SamlLoginRequest;
import org.folio.rest.jaxrs.model.SamlRegenerateResponse;
import org.folio.rest.jaxrs.model.SamlValidateGetType;
import org.folio.rest.jaxrs.model.SamlValidateResponse;
import org.folio.rest.jaxrs.resource.Saml;
import org.folio.rest.jaxrs.resource.Saml.PostSamlCallbackResponse.HeadersFor302;
import org.folio.rest.tools.client.HttpClientFactory;
import org.folio.rest.tools.client.interfaces.HttpClientInterface;
import org.folio.session.NoopSession;
import org.folio.util.Base64Util;
import org.folio.util.ConfigEntryUtil;
import org.folio.util.HttpActionMapper;
import org.folio.util.OkapiHelper;
import org.folio.util.UrlUtil;
import org.folio.util.VertxUtils;
import org.folio.util.model.OkapiHeaders;
import org.folio.util.model.UrlCheckResult;
import org.pac4j.core.authorization.authorizer.csrf.CsrfAuthorizer;
import org.pac4j.core.authorization.authorizer.csrf.DefaultCsrfTokenGenerator;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.vertx.VertxWebContext;
import org.springframework.util.StringUtils;

import io.vertx.core.AsyncResult;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.Session;
import io.vertx.ext.web.sstore.impl.SharedDataSessionImpl;

/**
 * Main entry point of module
 *
 * @author rsass
 */
public class SamlAPI implements Saml {

  private static final Logger log = LoggerFactory.getLogger(SamlAPI.class);
  public static final String QUOTATION_MARK_CHARACTER = "\"";

  /**
   * Check that client can be loaded, SAML-Login button can be displayed.
   */
  @Override
  public void getSamlCheck(RoutingContext routingContext, Map<String, String> okapiHeaders,
                           Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

//    Session session;
//    Cookie csrfTokenCookie = routingContext.getCookie(Pac4jConstants.CSRF_TOKEN);
//    if(csrfTokenCookie != null) {
//      session = new SharedDataSessionImpl(new PRNG(vertxContext.owner()));      
//      session.put(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie.getValue());
//    } else {
//      session = new NoopSession();
//    }
//    routingContext.setSession(session);
//    
//    final VertxWebContext webContext = VertxUtils.createWebContext(routingContext);
//    CsrfAuthorizer csrfAuth = new CsrfAuthorizer();
//    csrfAuth.setOnlyCheckPostRequest(false);
//    try {
//      if(!csrfAuth.isAuthorized(webContext, null)) {
//        asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond401WithTextPlain("CSRF attack")));
//        return;
//      }
//    } catch (HttpAction e2) {
//      asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond401WithTextPlain("CSRF attack")));
//      return;
//    }
    
    findSaml2Client(routingContext, false, false)
      .setHandler(samlClientHandler -> {
        if (samlClientHandler.failed()) {
          asyncResultHandler.handle(Future.succeededFuture(GetSamlCheckResponse.respond200WithApplicationJson(new SamlCheck().withActive(false))));
        } else {
          asyncResultHandler.handle(Future.succeededFuture(GetSamlCheckResponse.respond200WithApplicationJson(new SamlCheck().withActive(true))));
        }
      });
  }


  @Override
  public void postSamlLogin(SamlLoginRequest requestEntity, RoutingContext routingContext, Map<String, String> okapiHeaders,
                            Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    String stripesUrl = requestEntity.getStripesUrl();

    // register non-persistent session (this request only) to overWrite relayState
    Session session = new SharedDataSessionImpl(new PRNG(vertxContext.owner()));
    routingContext.setSession(session);
    
    findSaml2Client(routingContext, false, false) // do not allow login, if config is missing
      .setHandler(samlClientHandler -> {
        WebContext webContext = VertxUtils.createWebContext(routingContext);
 
        Response response;
        if (samlClientHandler.succeeded()) {
          SamlClientComposite composite = samlClientHandler.result();
          SAML2Client saml2Client = composite.getClient();          
          
//          String domain;
//          try {
//            URI uri = new URI(composite.getConfiguration().getOkapiUrl());
//            domain = uri.getHost();
//          } catch (URISyntaxException e) {
//            domain = "";
//          }
          
          String csrfToken = new DefaultCsrfTokenGenerator().get(webContext);
          Cookie cookie = Cookie.cookie("csrfToken", csrfToken);
//          cookie.setPath("/");
//          cookie.setDomain(domain);
          routingContext.addCookie(cookie);
          session.put("samlRelayState", stripesUrl + "?csrfToken=" + csrfToken);
          
          try {
            RedirectAction redirectAction = saml2Client.getRedirectAction(webContext);
            String responseJsonString = redirectAction.getContent();
            SamlLogin dto = Json.decodeValue(responseJsonString, SamlLogin.class);
            routingContext.response().headers().clear(); // saml2Client sets Content-Type: text/html header
            response = PostSamlLoginResponse.respond200WithApplicationJson(dto);
          } catch (HttpAction httpAction) {
            response = HttpActionMapper.toResponse(httpAction);
          }
        } else {
          log.warn("Login called but cannot load client to handle", samlClientHandler.cause());
          response = PostSamlLoginResponse.respond500WithTextPlain("Login called but cannot load client to handle");
        }
        asyncResultHandler.handle(Future.succeededFuture(response));
      });
  }


  @Override
  public void postSamlCallback(RoutingContext routingContext, Map<String, String> okapiHeaders,
                               Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    Session session;
    Cookie csrfTokenCookie = routingContext.getCookie("csrfToken");
//    if(csrfTokenCookie != null) {
//      session = new SharedDataSessionImpl(new PRNG(vertxContext.owner()));      
//      session.put("csrfToken", csrfTokenCookie.getValue());
//    } else {
      session = new NoopSession();
//    }
    routingContext.setSession(session);
    
    final VertxWebContext webContext = VertxUtils.createWebContext(routingContext);
//    CsrfAuthorizer csrfAuth = new CsrfAuthorizer();
//    csrfAuth.setOnlyCheckPostRequest(false);
//    try {
//      if(!csrfAuth.isAuthorized(webContext, null)) {
//        asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond401WithTextPlain("CSRF attack")));
//        return;
//      }
//    } catch (HttpAction e2) {
//      asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond401WithTextPlain("CSRF attack")));
//      return;
//    }

    final String relayState = webContext.getRequestParameter("RelayState"); // There is no better way to get RelayState.
    URI relayStateUrl = null;
    try {
      relayStateUrl = new URI(relayState);
    } catch (URISyntaxException e1) {
      asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond400WithTextPlain("Invalid relay state url: " + relayState)));
      return;
    }
    final URI originalUrl = relayStateUrl;
    final URI stripesBaseUrl = UrlUtil.parseBaseUrl(originalUrl);
    final String csrfToken = relayState.split("=")[1];
    if(csrfTokenCookie == null || csrfToken == null || !csrfTokenCookie.getValue().equals(csrfToken)) {
      asyncResultHandler.handle(Future.succeededFuture(
          PostSamlCallbackResponse.respond401WithTextPlain("CSRF Attempt")));
      return;
    }

    findSaml2Client(routingContext, false, false)
      .setHandler(samlClientHandler -> {
        if (samlClientHandler.failed()) {
          asyncResultHandler.handle(
            Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(samlClientHandler.cause().getMessage())));
        } else {
          try {
            final SamlClientComposite samlClientComposite = samlClientHandler.result();
            final SAML2Client client = samlClientComposite.getClient();
            final SamlConfiguration configuration = samlClientComposite.getConfiguration();
            String userPropertyName = configuration.getUserProperty() == null ? "externalSystemId" : configuration.getUserProperty();
            String samlAttributeName = configuration.getSamlAttribute() == null ? "UserID" : configuration.getSamlAttribute();


            SAML2Credentials credentials = client.getCredentials(webContext);

            // Get user id
            List samlAttributeList = (List) credentials.getUserProfile().getAttribute(samlAttributeName);
            if (samlAttributeList == null || samlAttributeList.isEmpty()) {
              asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond400WithTextPlain("SAML attribute doesn't exist: " + samlAttributeName)));
              return;
            }
            final String samlAttributeValue = samlAttributeList.get(0).toString();

            final String usersCql = userPropertyName +
              "=="
              + QUOTATION_MARK_CHARACTER + samlAttributeValue + QUOTATION_MARK_CHARACTER;

            final String userQuery = UriBuilder.fromPath("/users").queryParam("query", usersCql).build().toString();

            OkapiHeaders parsedHeaders = OkapiHelper.okapiHeaders(okapiHeaders);

            Map<String, String> headers = new HashMap<>();
            headers.put(OkapiHeaders.OKAPI_TOKEN_HEADER, parsedHeaders.getToken());

            HttpClientInterface usersClient = HttpClientFactory.getHttpClient(parsedHeaders.getUrl(), parsedHeaders.getTenant());
            usersClient.setDefaultHeaders(headers);
            usersClient.request(userQuery)
              .whenComplete((userQueryResponse, ex) -> {
                if (!org.folio.rest.tools.client.Response.isSuccess(userQueryResponse.getCode())) {
                  asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(userQueryResponse.getError().toString())));
                } else { // success
                  JsonObject resultObject = userQueryResponse.getBody();

                  int recordCount = resultObject.getInteger("totalRecords");
                  if (recordCount > 1) {
                    asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond400WithTextPlain("More than one user record found!")));
                  } else if (recordCount == 0) {
                    String message = "No user found by " + userPropertyName + " == " + samlAttributeValue;
                    log.warn(message);
                    asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond400WithTextPlain(message)));
                  } else {

                    final JsonObject userObject = resultObject.getJsonArray("users").getJsonObject(0);
                    String userId = userObject.getString("id");
                    if (!userObject.getBoolean("active")) {
                      asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond403WithTextPlain("Inactive user account!")));
                    } else {

                      JsonObject payload = new JsonObject().put("payload", new JsonObject().put("sub", userObject.getString("username")).put("user_id", userId));


                      HttpClientInterface tokenClient = HttpClientFactory.getHttpClient(parsedHeaders.getUrl(), parsedHeaders.getTenant());
                      tokenClient.setDefaultHeaders(headers);
                      try {
                        tokenClient.request(HttpMethod.POST, payload, "/token", null)
                          .whenComplete((tokenResponse, tokenError) -> {
                            if (!org.folio.rest.tools.client.Response.isSuccess(tokenResponse.getCode())) {
                              asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(tokenResponse.getError().toString())));
                            } else {
                              String candidateAuthToken = null;
                              if(tokenResponse.getCode() == 200) {
                                candidateAuthToken = tokenResponse.getHeaders().get(OkapiHeaders.OKAPI_TOKEN_HEADER);
                              } else { //mod-authtoken v2.x returns 201, with token in JSON response body
                                try {
                                  candidateAuthToken = tokenResponse.getBody().getString("token");
                                } catch(Exception e) {
                                  asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(e.getMessage())));
                                }
                              }
                              final String authToken = candidateAuthToken;

                              final String location = UriBuilder.fromUri(stripesBaseUrl)
                                .path("sso-landing")
                                .queryParam("ssoToken", authToken)
                                .queryParam("fwd", originalUrl.getPath())
                                .build()
                                .toString();

                              final String cookie = new NewCookie("ssoToken", authToken, "", originalUrl.getHost(), "", 3600, false).toString();

                              HeadersFor302 headers302 = PostSamlCallbackResponse.headersFor302().withSetCookie(cookie).withXOkapiToken(authToken).withLocation(location);
                              asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond302(headers302)));

                            }
                          });
                      } catch (Exception httpClientEx) {
                        asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(httpClientEx.getMessage())));
                      }
                    }

                  }

                }
              });


          } catch (HttpAction httpAction) {
            asyncResultHandler.handle(Future.succeededFuture(HttpActionMapper.toResponse(httpAction)));
          } catch (Exception ex) {
            String message = StringUtils.hasText(ex.getMessage()) ? ex.getMessage() : "Unknown error: " + ex.getClass().getName();
            asyncResultHandler.handle(Future.succeededFuture(PostSamlCallbackResponse.respond500WithTextPlain(message)));
          }
        }
      });
  }


  @Override
  public void getSamlRegenerate(RoutingContext routingContext, Map<String, String> okapiHeaders,
                                Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    regenerateSaml2Config(routingContext)
      .setHandler(regenerationHandler -> {
        if (regenerationHandler.failed()) {
          log.warn("Cannot regenerate SAML2 metadata.", regenerationHandler.cause());
          String message =
            "Cannot regenerate SAML2 matadata. Internal error was: " + regenerationHandler.cause().getMessage();
          asyncResultHandler
            .handle(Future.succeededFuture(GetSamlRegenerateResponse.respond500WithTextPlain(message)));
        } else {

          ConfigurationsClient.storeEntry(OkapiHelper.okapiHeaders(okapiHeaders), SamlConfiguration.METADATA_INVALIDATED_CODE, "false")
            .setHandler(configurationEntryStoredEvent -> {

              if (configurationEntryStoredEvent.failed()) {
                asyncResultHandler.handle(Future.succeededFuture(GetSamlRegenerateResponse.respond500WithTextPlain("Cannot persist metadata invalidated flag!")));
              } else {
                String metadata = regenerationHandler.result();

                Base64Util.encode(vertxContext, metadata)
                  .setHandler(base64Result -> {
                    if (base64Result.failed()) {
                      String message = base64Result.cause() == null ? "" : base64Result.cause().getMessage();
                      GetSamlRegenerateResponse response = GetSamlRegenerateResponse.respond500WithTextPlain("Cannot encode file content " + message);
                      asyncResultHandler.handle(Future.succeededFuture(response));
                    } else {
                      SamlRegenerateResponse responseEntity = new SamlRegenerateResponse()
                        .withFileContent(base64Result.result().toString(StandardCharsets.UTF_8));
                      asyncResultHandler.handle(Future.succeededFuture(GetSamlRegenerateResponse.respond200WithApplicationJson(responseEntity)));
                    }

                  });

              }
            });
        }
      });
  }

  @Override
  public void getSamlConfiguration(RoutingContext rc, Map<String, String> okapiHeaders, Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    ConfigurationsClient.getConfiguration(OkapiHelper.okapiHeaders(okapiHeaders))
      .setHandler(configurationResult -> {

        AsyncResult<SamlConfig> result = configurationResult.map(this::configToDto);

        if (result.failed()) {
          log.warn("Cannot load configuration", result.cause());
          asyncResultHandler.handle(
            Future.succeededFuture(
              GetSamlConfigurationResponse.respond500WithTextPlain("Cannot get configuration")));
        } else {
          asyncResultHandler.handle(Future.succeededFuture(GetSamlConfigurationResponse.respond200WithApplicationJson(result.result())));
        }

      });

  }


  @Override
  public void putSamlConfiguration(SamlConfigRequest updatedConfig, RoutingContext rc, Map<String, String> okapiHeaders, Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    checkConfigValues(updatedConfig, vertxContext.owner())
      .setHandler(checkValuesHandler -> {
        if (checkValuesHandler.failed()) {
          SamlValidateResponse errorEntity = new SamlValidateResponse().withValid(false).withError(checkValuesHandler.cause().getMessage());
          asyncResultHandler.handle(Future.succeededFuture(PutSamlConfigurationResponse.respond400WithApplicationJson(errorEntity)));
        } else {
          OkapiHeaders parsedHeaders = OkapiHelper.okapiHeaders(okapiHeaders);
          ConfigurationsClient.getConfiguration(parsedHeaders).setHandler((AsyncResult<SamlConfiguration> configRes) -> {
            if (configRes.failed()) {
              asyncResultHandler.handle(Future.succeededFuture(
                PutSamlConfigurationResponse.respond500WithTextPlain(configRes.cause() != null ? configRes.cause().getMessage() : "Cannot load current configuration")));
            } else {

              Map<String, String> updateEntries = new HashMap<>();

              SamlConfiguration config = configRes.result();

              ConfigEntryUtil.valueChanged(config.getIdpUrl(), updatedConfig.getIdpUrl().toString(), idpUrl -> {
                updateEntries.put(SamlConfiguration.IDP_URL_CODE, idpUrl);
                updateEntries.put(SamlConfiguration.METADATA_INVALIDATED_CODE, "true");
              });

              ConfigEntryUtil.valueChanged(config.getSamlBinding(), updatedConfig.getSamlBinding().toString(), samlBindingCode ->
                updateEntries.put(SamlConfiguration.SAML_BINDING_CODE, samlBindingCode));

              ConfigEntryUtil.valueChanged(config.getSamlAttribute(), updatedConfig.getSamlAttribute(), samlAttribute ->
                updateEntries.put(SamlConfiguration.SAML_ATTRIBUTE_CODE, samlAttribute));

              ConfigEntryUtil.valueChanged(config.getUserProperty(), updatedConfig.getUserProperty(), userProperty ->
                updateEntries.put(SamlConfiguration.USER_PROPERTY_CODE, userProperty));

              ConfigEntryUtil.valueChanged(config.getOkapiUrl(), updatedConfig.getOkapiUrl().toString(), okapiUrl -> {
                updateEntries.put(SamlConfiguration.OKAPI_URL, okapiUrl);
                updateEntries.put(SamlConfiguration.METADATA_INVALIDATED_CODE, "true");
              });

              storeConfigEntries(rc, asyncResultHandler, parsedHeaders, updateEntries);

            }
          });
        }
      });


  }

  private void storeConfigEntries(RoutingContext rc, Handler<AsyncResult<Response>> asyncResultHandler, OkapiHeaders parsedHeaders, Map<String, String> updateEntries) {
    ConfigurationsClient.storeEntries(parsedHeaders, updateEntries)
      .setHandler(configuratiuonSavedEvent -> {
        if (configuratiuonSavedEvent.failed()) {
          asyncResultHandler.handle(Future.succeededFuture(
            PutSamlConfigurationResponse.respond500WithTextPlain(configuratiuonSavedEvent.cause() != null ? configuratiuonSavedEvent.cause().getMessage() : "Cannot save configuration")));
        } else {
          findSaml2Client(rc, true, true)
            .setHandler(configurationLoadEvent -> {
              if (configurationLoadEvent.failed()) {
                asyncResultHandler.handle(Future.succeededFuture(
                  PutSamlConfigurationResponse.respond500WithTextPlain(configurationLoadEvent.cause() != null ? configurationLoadEvent.cause().getMessage() : "Cannot reload current configuration")));
              } else {

                SamlConfiguration newConf = configurationLoadEvent.result().getConfiguration();
                SamlConfig dto = configToDto(newConf);

                asyncResultHandler.handle(Future.succeededFuture(PutSamlConfigurationResponse.respond200WithApplicationJson(dto)));

              }
            });
        }
      });
  }


  @Override
  public void getSamlValidate(SamlValidateGetType type, String value, Map<String, String> okapiHeaders, Handler<AsyncResult<Response>> asyncResultHandler, Context vertxContext) {

    Handler<AsyncResult<UrlCheckResult>> handler = hnd -> {
      if (hnd.succeeded()) {
        UrlCheckResult result = hnd.result();
        SamlValidateResponse response = new SamlValidateResponse();
        if (result.isSuccess()) {
          response.setValid(true);
        } else {
          response.setValid(false);
          response.setError(result.getMessage());
        }
        asyncResultHandler.handle(Future.succeededFuture(GetSamlValidateResponse.respond200WithApplicationJson(response)));
      } else {
        asyncResultHandler.handle(Future.succeededFuture(GetSamlValidateResponse.respond500WithTextPlain("unknown error")));
      }
    };

    switch (type) {
      case IDPURL:
        UrlUtil.checkIdpUrl(value, vertxContext.owner()).setHandler(handler);
        break;
      default:
        asyncResultHandler.handle(Future.succeededFuture(GetSamlValidateResponse.respond500WithTextPlain("unknown type: " + type.toString())));
    }


  }

  private Future<Void> checkConfigValues(SamlConfigRequest updatedConfig, Vertx vertx) {

    Promise<Void> result = Promise.promise();

    List<Future> futures = Arrays.asList(UrlUtil.checkIdpUrl(updatedConfig.getIdpUrl().toString(), vertx));

    CompositeFuture.all(futures)
      .setHandler(hnd -> {
        if (hnd.succeeded()) {
          // all success
          Optional<Future> failedCheck = futures.stream()
            .filter(future -> !((UrlCheckResult) future.result()).getStatus().equals(UrlCheckResult.Status.SUCCESS))
            .findFirst();

          if (failedCheck.isPresent()) {
            Future<UrlCheckResult> future = failedCheck.get();
            UrlCheckResult urlCheckResult = future.result();
            result.fail(urlCheckResult.getMessage());

          } else {
            result.complete();
          }
        } else {
          result.fail(hnd.cause());
        }
      });

    return result.future();

  }

  private Future<String> regenerateSaml2Config(RoutingContext routingContext) {

    Promise<String> result = Promise.promise();
    final Vertx vertx = routingContext.vertx();

    findSaml2Client(routingContext, false, false) // generate KeyStore if missing
      .setHandler(handler -> {
        if (handler.failed()) {
          result.fail(handler.cause());
        } else {
          SAML2Client saml2Client = handler.result().getClient();

          vertx.executeBlocking(blockingCode -> {

            SAML2ClientConfiguration cfg = saml2Client.getConfiguration();

            // force metadata generation then init
            cfg.setForceServiceProviderMetadataGeneration(true);
            saml2Client.reinit(VertxUtils.createWebContext(routingContext));
            cfg.setForceServiceProviderMetadataGeneration(false);

            blockingCode.complete(saml2Client.getServiceProviderMetadataResolver().getMetadata());

          }, result);
        }
      });

    return result.future();
  }

  /**
   * @param routingContext        the actual routing context
   * @param generateMissingConfig if the encryption key and passwords are missing should we generate and store it?
   * @param reloadClient          should we drop the loaded client and reload it with (maybe modified) configuration?
   * @return Future of loaded {@link SAML2Client} or failed future if it cannot be loaded.
   */
  private Future<SamlClientComposite> findSaml2Client(RoutingContext routingContext, boolean generateMissingConfig, boolean reloadClient) {

    String tenantId = OkapiHelper.okapiHeaders(routingContext).getTenant();
    SamlConfigHolder configHolder = SamlConfigHolder.getInstance();


    SamlClientComposite clientComposite = configHolder.findClient(tenantId);

    if (clientComposite != null && !reloadClient) {
      return Future.succeededFuture(clientComposite);
    } else {
      if (reloadClient) {
        configHolder.removeClient(tenantId);
      }

      Promise<SamlClientComposite> result = Promise.promise();
      SamlClientLoader.loadFromConfiguration(routingContext, generateMissingConfig)
        .setHandler(clientResult -> {
          if (clientResult.failed()) {
            result.fail(clientResult.cause());
          } else {
            SamlClientComposite newClientComposite = clientResult.result();
            configHolder.putClient(tenantId, newClientComposite);
            result.complete(newClientComposite);
          }
        });
      return result.future();
    }

  }

  /**
   * Registers a no-op session. Pac4j want to access session variablas and fails if there is no session.
   *
   * @param routingContext the current routing context
   */
  private void registerFakeSession(RoutingContext routingContext) {
    routingContext.setSession(new NoopSession());
  }

  /**
   * Converts internal {@link SamlConfiguration} object to DTO, checks illegal values
   */
  private SamlConfig configToDto(SamlConfiguration config) {
    SamlConfig samlConfig = new SamlConfig()
      .withSamlAttribute(config.getSamlAttribute())
      .withUserProperty(config.getUserProperty())
      .withMetadataInvalidated(Boolean.valueOf(config.getMetadataInvalidated()));
    try {
      URI uri = URI.create(config.getOkapiUrl());
      samlConfig.setOkapiUrl(uri);
    } catch (Exception e) {
      log.debug("Okapi URI is in a bad format");
      samlConfig.setOkapiUrl(URI.create(""));
    }

    try {
      URI uri = URI.create(config.getIdpUrl());
      samlConfig.setIdpUrl(uri);
    } catch (Exception x) {
      samlConfig.setIdpUrl(URI.create(""));
    }

    try {
      SamlConfig.SamlBinding samlBinding = SamlConfig.SamlBinding.fromValue(config.getSamlBinding());
      samlConfig.setSamlBinding(samlBinding);
    } catch (Exception x) {
      samlConfig.setSamlBinding(null);
    }

    return samlConfig;
  }

}
