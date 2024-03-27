package com.js9.secureapi.data_initializer;

import com.js9.secureapi.auth.request.AuthenticationRequest;
import com.js9.secureapi.auth.request.RegisterRequest;
import com.js9.secureapi.auth.response.AuthenticationResponse;
import com.js9.secureapi.auth.service.AuthenticationService;
import com.js9.secureapi.domain.entities.UserEntity;
import com.js9.secureapi.domain.enums.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {
    private final AuthenticationService authenticationService;

    @Override
    public void run(String... args) throws Exception {
        var admin = RegisterRequest
                .builder()
                .firstName("Admin1")
                .lastName("Admin")
                .email("admin@testmail.com")
                .password("admin-pass")
                .role(Role.ADMIN)
                .build();

        var manager = RegisterRequest
                .builder()
                .firstName("Manager1")
                .lastName("Manager")
                .email("manager@testmail.com")
                .password("manager-pass")
                .role(Role.MANAGER)
                .build();

        AuthenticationResponse adminReg = authenticationService.register(admin);
        AuthenticationResponse managerReg = authenticationService.register(manager);

        var adminAuthRequest =
                AuthenticationRequest
                        .builder()
                        .email("admin@testmail.com")
                        .password("admin-pass")
                        .build();

        var managerAuthRequest =
                AuthenticationRequest
                        .builder()
                        .email("manager@testmail.com")
                        .password("manager-pass").build();

        AuthenticationResponse adminAuthResponse = authenticationService.authenticate(adminAuthRequest);
        AuthenticationResponse managerAuthResponse = authenticationService.authenticate(managerAuthRequest);

        log.info("ADMIN TOKEN:: " + adminAuthResponse.getToken());
        log.info("MANAGER TOKEN:: "+ managerAuthResponse.getToken());


    }
}
