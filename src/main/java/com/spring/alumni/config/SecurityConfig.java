package com.spring.alumni.config;

import com.spring.alumni.security.JwtAuthFilter;
import com.spring.alumni.security.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

        httpSecurity
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sessionConfig -> sessionConfig
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .oauth2Login(oAuth2 -> oAuth2
//                        .failureHandler(
//                                (request, response, exception) ->
//                                    log.error("oAuth2 error", exception)
//                        ).successHandler(oAuth2SuccessHandler)
//
//                );
                .oauth2Login(oauthLoginConfig -> oauthLoginConfig
                        .authorizationEndpoint((authorizationEndpointConfig ->
                                authorizationEndpointConfig.authorizationRequestResolver(
                                        requestResolver(clientRegistrationRepository) // See this.
                                ))
                        ).successHandler(oAuth2SuccessHandler));
        return httpSecurity.build();

    }


    private static OAuth2AuthorizationRequestResolver requestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );

        resolver.setAuthorizationRequestCustomizer(customizer -> customizer
                .attributes(attrs -> {
                    String registrationId = (String) attrs.get(OAuth2ParameterNames.REGISTRATION_ID);
                    if ("linkedin".equalsIgnoreCase(registrationId)) {
                        attrs.remove(OidcParameterNames.NONCE);
                    }
                })
                .parameters(params -> {
                    String registrationId = (String) params.get(OAuth2ParameterNames.REGISTRATION_ID);
                    if ("linkedin".equalsIgnoreCase(registrationId)) {
                        params.remove(OidcParameterNames.NONCE);
                    }
                })
        );

        return resolver;
    }



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
