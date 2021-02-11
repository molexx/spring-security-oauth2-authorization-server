package oauth.server.sample;

import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;

import io.jzheaux.springsecurity.ClientInformationUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;



@Service("oauthServerClientDetailsService")
public class SampleClientDetailsService implements UserDetailsService {

	ClientInformation sampleClientOne;

	public SampleClientDetailsService() {
		ClientMetadata clientOneMetadata = new ClientMetadata();
		clientOneMetadata.setScope(new Scope(//"message:read", "message:write",
				"profile"));
		clientOneMetadata.setGrantTypes(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.PASSWORD, GrantType.CLIENT_CREDENTIALS)));
		clientOneMetadata.setName("Demo Client One");
		clientOneMetadata.setRedirectionURI(URI.create("http://localhost:8080/login/oauth2/code/sso"));
		this.sampleClientOne = new ClientInformation(
				new ClientID("client1"),
				new Date(0),
				clientOneMetadata,
				new Secret("{noop}client1sSecret"));
	}

	@Override
	public UserDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {
		if (clientId.equals(this.sampleClientOne.getID().getValue())) {
			return new ClientInformationUserDetails(this.sampleClientOne);
		}
		throw new UsernameNotFoundException("couldn't find client");
	}

}
