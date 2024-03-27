package com.js9.secureapi.securityConfig;

import com.js9.secureapi.domain.enums.Permissions;
import com.js9.secureapi.domain.enums.Role;
import com.js9.secureapi.jwtUtil.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.js9.secureapi.domain.enums.Permissions.*;
import static com.js9.secureapi.domain.enums.Role.*;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    public static final String[] WHITELABEL_URL = {"/api/v1/auth/register", "/api/v1/auth/authenticate"};
    public static final String MANAGEMENT_URL = "/api/v1/management/**";
    public static final String ADMIN_URL = "/api/v1/admin/**";
    public static final String[] MANAGEMENT_URL_PERMITTED_ROLES = {ADMIN.name(), MANAGER.name()};
    public static final String[] ADMIN_URL_PERMITTED_ROLES = {ADMIN.name()};

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

       http
               .csrf(AbstractHttpConfigurer::disable)
               .authorizeHttpRequests(request-> request
                       .requestMatchers(WHITELABEL_URL)
                       .permitAll()
                       .requestMatchers(MANAGEMENT_URL).hasAnyRole(MANAGEMENT_URL_PERMITTED_ROLES)
                       .requestMatchers(GET, MANAGEMENT_URL).hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                       .requestMatchers(POST, MANAGEMENT_URL).hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                       .requestMatchers(PUT, MANAGEMENT_URL).hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                       .requestMatchers(DELETE, MANAGEMENT_URL).hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())


                       .requestMatchers(ADMIN_URL).hasRole(ADMIN.name())
                       .requestMatchers(GET, ADMIN_URL).hasAuthority(ADMIN_READ.name())
                       .requestMatchers(POST, ADMIN_URL).hasAuthority(ADMIN_CREATE.name())
                       .requestMatchers(PUT, ADMIN_URL).hasAuthority(ADMIN_UPDATE.name())
                       .requestMatchers(DELETE, ADMIN_URL).hasAuthority(ADMIN_DELETE.name())
                       .anyRequest()
                       .authenticated())
               .sessionManagement(sessionManager -> sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .authenticationProvider(authenticationProvider)
               .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


       return http.build();
   }
}
