package com.js9.secureapi.auth;

import com.js9.secureapi.auth.request.AuthenticationRequest;
import com.js9.secureapi.auth.request.RegisterRequest;
import com.js9.secureapi.auth.response.AuthenticationResponse;
import com.js9.secureapi.auth.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {


    private final AuthenticationService authenticationService;

    @PostMapping(path = "/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){

        return new ResponseEntity<>(authenticationService.register(request), HttpStatus.CREATED);

    }

    @PostMapping(path = "/authenticate")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody AuthenticationRequest request){
        return new ResponseEntity<>(authenticationService.authenticate(request), HttpStatus.OK);
    }

}
