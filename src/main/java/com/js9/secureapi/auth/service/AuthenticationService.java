package com.js9.secureapi.auth.service;

import com.js9.secureapi.auth.request.AuthenticationRequest;
import com.js9.secureapi.auth.request.RegisterRequest;
import com.js9.secureapi.auth.response.AuthenticationResponse;
import com.js9.secureapi.domain.entities.UserEntity;
import com.js9.secureapi.domain.enums.Role;
import com.js9.secureapi.jwtUtil.CustomUserDetailsService;
import com.js9.secureapi.jwtUtil.JwtService;
import com.js9.secureapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final CustomUserDetailsService userDetailsService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {

//        if(userRepository.findByEmail(request.getEmail()).isPresent()) throw new UserAlreadyExistException();

        var newUser = UserEntity.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(newUser);
        //generate token
        return getAuthenticationResponse(newUser);

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        }catch (AuthenticationException e){
            log.info("An error occurred. " + e.getMessage());
        }

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        return getAuthenticationResponse(user);
    }

    private AuthenticationResponse getAuthenticationResponse(UserEntity user) {
        String token = jwtService.generateJwtToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }
}
