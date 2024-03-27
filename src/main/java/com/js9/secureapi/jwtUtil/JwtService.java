package com.js9.secureapi.jwtUtil;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

public interface JwtService {

    String extractUsername(String token);

    Claims extractAllClaims(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimResolver);

    String generateJwtToken(Map<String, Object> extraClaims, UserDetails userDetails);

    String generateJwtToken(UserDetails userDetails);


    Boolean isTokenValid(String token, UserDetails userDetails);

}
