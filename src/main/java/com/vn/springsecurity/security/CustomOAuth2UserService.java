package com.vn.springsecurity.security;

import com.vn.springsecurity.enums.Role;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final OidcUserService oidcUserService = new OidcUserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        log.info(">>> [OAuth2] CustomOAuth2UserService loadUser is called");
        OAuth2User oauth2User = super.loadUser(userRequest);
        return processUser(userRequest, oauth2User);
    }

    public OidcUser loadUser(OidcUserRequest userRequest) {
        log.info(">>> [OIDC] CustomOAuth2UserService loadUser is called");
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);
        return (OidcUser) processUser(userRequest, oidcUser);
    }

    private OAuth2User processUser(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // Inclusive email and providerId
        String providerId = oauth2User.getAttribute("sub");
        String email = oauth2User.getAttribute("email");
        String fistName = oauth2User.getAttribute("given_name");
        String lastName = oauth2User.getAttribute("family_name");

        if (oauth2User instanceof OidcUser oidcUser) {
            providerId = oidcUser.getIdToken().getSubject();
            email = oidcUser.getEmail();
        }

        // Get user from a database or create a new one if not exist
        String finalEmail = email;
        String finalProviderId = providerId;
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(finalEmail);
            newUser.setProvider(registrationId.toUpperCase());
            newUser.setProviderId(finalProviderId);
            newUser.setFirstName(fistName);
            newUser.setLastName(lastName);
            newUser.setRole(Role.USER); // Default role is USER
            return userRepository.save(newUser);
        });
        return buildOAuth2User(user, oauth2User);
    }

    private OAuth2User buildOAuth2User(User user, OAuth2User oauth2User) {
        List<SimpleGrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));

        if (oauth2User instanceof OidcUser oidcUser) {
            return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), "email");
        }
        return new DefaultOAuth2User(authorities, oauth2User.getAttributes(), "email");
    }
}
