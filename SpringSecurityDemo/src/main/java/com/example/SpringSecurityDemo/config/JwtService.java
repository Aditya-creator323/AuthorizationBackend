package com.example.SpringSecurityDemo.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3ee616673dc887ab58a2250943c208bee05a1107aa8cb2664a16d92114641f34";   // This will be used in getSigninKey() method

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);                             // for extracting the username from the jwt
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {           // This for extracting one single Claim
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // It will generate Token without extraClaims by only using userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
        Map<String, Object> extraClaims,
        UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigniInKey())
                .compact();
    }

    // Method to valid a token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()                              // To parse the token
                .verifyWith(getSigniInKey())        // When we try to decode the token we need signingkey, It is used to create a signature part of Jwt
                .build()    
                .parseSignedClaims(token)                  // Once the object is build we will parse token by calling this method
                .getPayload();                             // Within the getPayload we can get all the claims that we have in this token
    }

    private SecretKey getSigniInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
