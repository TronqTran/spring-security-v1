package com.vn.springsecurity.config;

import com.vn.springsecurity.enums.Permission;
import com.vn.springsecurity.enums.Role;
import com.vn.springsecurity.security.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationProvider authenticationProvider,
                                                   JwtAuthenticationConverter jwtAuthenticationConverter,
                                                   CustomAccessDeniedHandler customAccessDeniedHandler,
                                                   CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                                                   CustomOAuth2UserService customOAuth2UserService,
                                                   OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                                                   JwtDecoder jwtDecoder,
                                                   CustomLogoutHandler customLogoutHandler,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authenticationProvider(authenticationProvider);
        http.authorizeHttpRequests(httpSecurityAuthorizeHttpRequestsConfigurer ->
                httpSecurityAuthorizeHttpRequestsConfigurer
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers("/api/v1/email/request-otp", "/api/v1/users/reset-password").permitAll()
                        .requestMatchers("/api/v1/hello/private").hasRole(Role.USER.name())
                        .requestMatchers("/api/v1/hello/admin").hasRole(Role.ADMIN.name())
                        .requestMatchers(HttpMethod.GET, "/api/v1/admin").hasAuthority(Permission.ADMIN_READ.getPermission())
                        .requestMatchers(HttpMethod.POST, "/api/v1/management").hasAuthority(Permission.MANAGER_CREATE.getPermission())
                        .anyRequest().authenticated()
        );
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer ->
                httpSecurityOAuth2ResourceServerConfigurer
                        .jwt(jwtConfigurer -> jwtConfigurer
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)
                                .decoder(jwtDecoder))
                        .accessDeniedHandler(customAccessDeniedHandler)
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
        );
        http.oauth2Login(httpSecurityOAuth2LoginConfigurer ->
                httpSecurityOAuth2LoginConfigurer
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                                .userService(customOAuth2UserService)
                                .oidcUserService(customOAuth2UserService::loadUser))
                        .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig.baseUri("/api/v1/oauth2/authorize"))
                        .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig.baseUri("/api/v1/oauth2/callback/*"))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
        );
        http.logout(logoutConfigurer ->
                logoutConfigurer
                        .logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(customLogoutHandler)
                        .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
        );
        return http.build();
    }
}
