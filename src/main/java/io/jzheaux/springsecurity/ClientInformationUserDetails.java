package io.jzheaux.springsecurity;

import com.nimbusds.oauth2.sdk.client.ClientInformation;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

public class ClientInformationUserDetails extends ClientInformation implements UserDetails, CredentialsContainer {

    private String password;
    private Collection<GrantedAuthority> authorities;

    public ClientInformationUserDetails(ClientInformation client) {
        super(client.getID(), client.getIDIssueDate(), client.getMetadata(), null);
        password = client.getSecret().getValue();

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_CLIENT"));
        authorities.addAll(client.getMetadata().getGrantTypes().stream()
                .map(grantType -> new SimpleGrantedAuthority("ROLE_" + grantType))
                .collect(Collectors.toList()));
        this.authorities = Collections.unmodifiableCollection(authorities);
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return super.getID().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
}
