package io.jzheaux.springsecurity;

import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@ConditionalOnProperty(prefix = "io.zheaux.springsecurity", name = {"enabled"}, havingValue = "true")
@RequestMapping("${io.zheaux.springsecurity.mvcprefix}")
public class OAuth2AuthorizationServerController {
	@Autowired
	private Cache authorizationCodeCache;

	@Autowired
	private Cache accessTokenCache;

	@Autowired
	private Cache refreshTokenCache;

	@Autowired
	@Qualifier("oauthServerClientDetailsService")
	private UserDetailsService oauthServerClientDetailsService;

	@Autowired
	AuthenticationManager endUserAuthenticationManager;
	
	@Value("${issuerUri}")
	String issuer;
	
	@Value("${io.zheaux.springsecurity.mvcprefix}")
	String mvcPrefix;

	@Value("${io.zheaux.springsecurity.allowAnyRedirectUrl:false}")
	Boolean allowAnyRedirectUrl;
	
	//TODO how to provide scopes if they are determined at runtime e.g. from a database?
	@Value("${io.zheaux.springsecurity.scopes}")
	String[] scopesForMetadata;

	
	@GetMapping(".well-known/openid-configuration")
	public HTTPResponse openidConfiguration() {
		//System.out.println("controller.openidConfiguration(): .well-known/openid-configuration called");
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(
				new Issuer(issuer + mvcPrefix),
				Arrays.asList(SubjectType.PUBLIC),
				URI.create(issuer + mvcPrefix +  "/jwks"));
		metadata.setAuthorizationEndpointURI(URI.create(this.issuer + mvcPrefix + "/authorize"));
		metadata.setTokenEndpointURI(URI.create(this.issuer + mvcPrefix + "/token"));
		metadata.setUserInfoEndpointURI(URI.create(this.issuer + mvcPrefix + "/userinfo"));
		metadata.setResponseTypes(Arrays.asList(ResponseType.getDefault()));
		//metadata.setResponseTypes(Arrays.asList(new ResponseType(ResponseType.Value.TOKEN)));  // Access token, with optional refresh token.
		metadata.setIDTokenJWSAlgs(Arrays.asList(JWSAlgorithm.RS256));
		//metadata.setScopes(new Scope("profile", "message:read", "message:write"));
		metadata.setScopes(new Scope(scopesForMetadata));
		HTTPResponse response = new HTTPResponse(200);
		response.setContent(metadata.toJSONObject().toString());
		return response;
	}
	
	
	public interface OpenIdUserInfoFactory {
		UserInfo create(OAuth2AuthenticatedPrincipal user);
	}
	
	@Autowired(required = false)
	OpenIdUserInfoFactory openIdUserInfoFactory;
	
	
	@GetMapping("userinfo")
	public HTTPResponse userinfo(HTTPRequest req, @AuthenticationPrincipal Principal auth, @AuthenticationPrincipal ClientInformation client) throws ParseException {
		//System.out.println("controller.userinfo(): /userinfo called, auth: " + auth + ", client: " + client);
		UserInfo info = null;
		if (openIdUserInfoFactory != null) {
			BearerTokenAuthentication bearerAuth = (BearerTokenAuthentication)auth;
			//System.out.println("controller.userinfo(): /userinfo called, bearerAuth.getDetails(): " + bearerAuth.getDetails());
			OAuth2AccessToken token = bearerAuth.getToken();
			//System.out.println("controller.userinfo(): /userinfo called, bearerAuth.getToken(): " + token);
			
			OAuth2AuthenticatedPrincipal user = (OAuth2AuthenticatedPrincipal) bearerAuth.getPrincipal();   //DefaultOAuth2AuthenticatedPrincipal


			//AuthorizationRequest request = AuthorizationRequest.parse(req);
			//System.out.println("controller.userinfo(): /userinfo called with request.getClientID().getValue(): '" + request.getClientID().getValue() + "'");
					
			info = openIdUserInfoFactory.create(user);
		} else {
			//default to a simple implementation
			Subject subject = new Subject(auth.getName());
			info = new UserInfo(subject);
		}
		return new UserInfoSuccessResponse(info).toHTTPResponse();
	}
	
	@PostMapping(path="introspect")
	public HTTPResponse introspect(HTTPRequest req) throws Exception {
		TokenIntrospectionRequest request = TokenIntrospectionRequest.parse(req);
		//TokenIntrospectionResponse response = this.accessTokenCache.get(request.getToken().getValue(), TokenIntrospectionResponse.class);
		TokenIntrospectionSuccessResponse response = deserialiseTokenIntrospectionSuccessResponse(this.accessTokenCache.get(request.getToken().getValue(), String.class));
		if (response == null) {
			response = new TokenIntrospectionSuccessResponse.Builder(false).build();
		}
		return response.toHTTPResponse();
	}


	
	public interface OauthUserNameProvider {
		String getUsername(ClientInformationUserDetails client, Principal user);
	}
	
	@ConditionalOnMissingBean(OauthUserNameProvider.class)
	@Bean
	OauthUserNameProvider defaultOauthUserNameProvider() {
		return new OauthUserNameProvider() {
			@Override
			public String getUsername(ClientInformationUserDetails client, Principal user) {
				String name = user.getName();
				//System.out.println("defaultOauthUserNameProvider.getUsername(): using user ('" + user + "').getName(): " + name);
				return name;
			}
		};
	}

	/**
	 * Configure a UsernameProvider to set the oauth user's root subject (name). Default implementation will call user.getName() which will be whatever the configured UserDetailsService sets as the name
	 */
	@Autowired
	OauthUserNameProvider oauthUsernameProvider;
	
	
	@GetMapping(path="authorize", params="response_type=code")
	public ModelAndView authorize(HTTPRequest req, @AuthenticationPrincipal Principal user) throws Exception {
		//System.out.println("controller.authorize(): /authorize?response_type=code called with req headers: " + req.getHeaderMap());
		//System.out.println("controller.authorize(): /authorize?response_type=code called with req query: " + req.getQuery());
		//System.out.println("controller.authorize(): /authorize?response_type=code called with user: " + user);
		AuthorizationRequest request = AuthorizationRequest.parse(req);
		//System.out.println("controller.authorize(): /authorize?response_type=code called with request.getClientID().getValue(): '" + request.getClientID().getValue() + "'");
		ClientInformation client = (ClientInformation)this.oauthServerClientDetailsService.loadUserByUsername(request.getClientID().getValue());
		if (client == null) {
			String error = new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,request.getState(), request.getResponseMode()).toHTTPResponse().getContent();
			throw new IllegalArgumentException(error);
		}
		
		URI redirectToUri;
		if (allowAnyRedirectUrl && client.getMetadata().getRedirectionURI() == null) {
			System.out.println("WARNING: io.zheaux.springsecurity.allowAnyRedirectUrl is true and client.getMetadata().getRedirectionURI() returned null, allowing any redirect URL");
			redirectToUri = request.getRedirectionURI();
		} else if (client.getMetadata().getRedirectionURI() == null || (!client.getMetadata().getRedirectionURI().equals(request.getRedirectionURI()))) {
			String error = new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT, request.getState(), request.getResponseMode()).toHTTPResponse().getContent();
			System.out.println("Unexpected redirection url, error: " + error + ", request.getRedirectionURI(): '" + request.getRedirectionURI() + "', client.getMetadata().getRedirectionURI(): '" + client.getMetadata().getRedirectionURI() + "'");
			throw new IllegalArgumentException(error);
		} else {
			redirectToUri = client.getMetadata().getRedirectionURI();
		}
		
		
		String oauthUserName = oauthUsernameProvider.getUsername((ClientInformationUserDetails)client, user);
		TokenIntrospectionSuccessResponse details = tokenDetails(client, new Subject(oauthUserName), request.getScope());
		Tokens tokens = accessAndRefreshTokens(details);  //calls accessToken() which stores the TokenIntrospectionSuccessResponse in accessTokenCache 
		AuthorizationCode code = new AuthorizationCode();
		//this.authorizationCodeCache.put(code.getValue(), tokens);
		this.authorizationCodeCache.put(code.getValue(), tokens.toJSONObject().toJSONString());
		
		String redirect = UriComponentsBuilder.fromUri(redirectToUri) //client.getMetadata().getRedirectionURI())
				.queryParam("code", code)
				.queryParam("state", request.getState().getValue())
				.build().toUriString();
		
		
		System.out.println("authorize(): returning ModelAndView redirecting to: " + redirect);
		
		return new ModelAndView("redirect:" + redirect);
	}

	@PostMapping(path="token", params="grant_type=authorization_code")
	public HTTPResponse authorizationCode(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		//System.out.println("controller.authorizationCode(): /token?grant_type=authorization_code called with req headers: " + req.getHeaderMap());

		TokenRequest request = TokenRequest.parse(req);

		AuthorizationCodeGrant grant = (AuthorizationCodeGrant) request.getAuthorizationGrant();
		if (allowAnyRedirectUrl && client.getMetadata().getRedirectionURI() == null) {
			System.out.println("WARNING: /token: io.zheaux.springsecurity.allowAnyRedirectUrl is true and client.getMetadata().getRedirectionURI() returned null, allowing any redirect URL");
		} else if (client.getMetadata().getRedirectionURI() == null || (!client.getMetadata().getRedirectionURI().equals(grant.getRedirectionURI()))) {
			System.out.println("WARNING: /token: request's grant's redirect URL '" + grant.getRedirectionURI() + "' does not match client's configured redirect url: '" + client.getMetadata().getRedirectionURI() + "'");
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}
		
		//Tokens tokens = this.authorizationCodeCache.get(grant.getAuthorizationCode().getValue(), Tokens.class));
		String code = grant.getAuthorizationCode().getValue();
		if (code == null || code.length() == 0) {
			System.out.println("WARNING: /token: called with null authorizationCode");
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}
		
		String cachedJson = this.authorizationCodeCache.get(code, String.class);
		if (cachedJson == null) {
			System.out.println("WARNING: /token: called with authorizationCode that is not in the authorizationCodeCache");
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}
		Tokens tokens = Tokens.parse(JSONObjectUtils.parse(cachedJson));
		if (tokens == null) {
			System.out.println("WARNING: /token: called with authorizationCode that was in the authorizationCodeCache but contained unparseable json");
			return new TokenErrorResponse(OAuth2Error.SERVER_ERROR).toHTTPResponse();
		}
		
		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	@PostMapping(path="token", params="grant_type=client_credentials")
	public HTTPResponse clientCredentials(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		//System.out.println("controller.clientCredentials(): /token?grant_type=client_credentials called with req headers: " + req.getHeaderMap());
		TokenRequest request = TokenRequest.parse(req);
		TokenIntrospectionSuccessResponse details = tokenDetails(client, new Subject(client.getID().getValue()), request.getScope());
		BearerAccessToken bearer = accessToken(details);
		Tokens tokens = new Tokens(bearer, null);
		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	@PostMapping(path="/token", params="grant_type=password")
	public HTTPResponse passwordGrant(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		//System.out.println("controller.passwordGrant(): /token?grant_type=password called with req headers: " + req.getHeaderMap());
		TokenRequest request = TokenRequest.parse(req);
		ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant) request.getAuthorizationGrant();
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(grant.getUsername(), grant.getPassword().getValue());
		Authentication authentication = this.endUserAuthenticationManager.authenticate(token);

		if (authentication.isAuthenticated()) {
			TokenIntrospectionSuccessResponse details = tokenDetails(client, new Subject(authentication.getName()), request.getScope());
			BearerAccessToken bearer = accessToken(details);
			Tokens tokens = new Tokens(bearer, null);
			return new AccessTokenResponse(tokens).toHTTPResponse();
		} else {
			throw new AccessDeniedException("access is denied");
		}
	}

	@PostMapping(path="token", params="grant_type=refresh_token")
	public HTTPResponse refreshToken
			(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		//System.out.println("controller.refreshToken(): /token?grant_type=refresh_token called with req headers: " + req.getHeaderMap());
		TokenRequest request = TokenRequest.parse(req);
		RefreshTokenGrant grant = (RefreshTokenGrant) request.getAuthorizationGrant();
		RefreshToken refreshToken = grant.getRefreshToken();
		//TokenIntrospectionResponse response = this.refreshTokenCache.get(refreshToken.getValue(), TokenIntrospectionResponse.class);
		TokenIntrospectionSuccessResponse response = deserialiseTokenIntrospectionSuccessResponse(this.refreshTokenCache.get(refreshToken.getValue(), String.class));

		if (response == null) {
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}

		TokenIntrospectionSuccessResponse token = response.toSuccessResponse();
		if (!token.getClientID().equals(client.getID())) {
			return new TokenErrorResponse(OAuth2Error.INVALID_CLIENT).toHTTPResponse();
		}

		Tokens tokens = accessAndRefreshTokens(token);
		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	private BearerAccessToken accessToken(TokenIntrospectionSuccessResponse details) {
		BearerAccessToken bearer = new BearerAccessToken(3600L, details.getScope());
		//this.accessTokenCache.put(bearer.getValue(), details);
		this.accessTokenCache.put(bearer.getValue(), serialiseTokenIntrospectionSuccessResponse(details));
		return bearer;
	}
	
	private static String serialiseTokenIntrospectionSuccessResponse(TokenIntrospectionSuccessResponse details) {
		return(details.toJSONObject().toJSONString());
	}
	
	static TokenIntrospectionSuccessResponse deserialiseTokenIntrospectionSuccessResponse(String str) throws ParseException {
		JSONObject jobj = JSONObjectUtils.parse(str);
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse(jobj);
		return(response);
	}
	
	private Tokens accessAndRefreshTokens(TokenIntrospectionSuccessResponse details) {
		BearerAccessToken bearer = accessToken(details);
		RefreshToken refreshToken = new RefreshToken();
		//this.refreshTokenCache.put(refreshToken.getValue(), details);
		this.refreshTokenCache.put(refreshToken.getValue(), serialiseTokenIntrospectionSuccessResponse(details));
		return new Tokens(bearer, refreshToken);
	}

	private TokenIntrospectionSuccessResponse tokenDetails(ClientInformation client, Subject subject, Scope requestedScope) {
		Scope scope = new Scope(client.getMetadata().getScope());
		scope.retainAll(requestedScope);
		BearerAccessToken bearer = new BearerAccessToken(3600L, scope);
		Date now = new Date();
		return new TokenIntrospectionSuccessResponse.Builder(true)
				.scope(scope)
				.clientID(client.getID())
				.expirationTime(new Date(now.getTime() + bearer.getLifetime()*1000))
				.issueTime(now)
				.issuer(new Issuer(this.issuer))
				.subject(subject)
				.build();
	}
}
