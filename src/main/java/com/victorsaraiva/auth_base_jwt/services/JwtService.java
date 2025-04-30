package com.victorsaraiva.auth_base_jwt.services;

import com.victorsaraiva.auth_base_jwt.models.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  @Value("${security.access-jwt.secret}")
  private String SECRET;

  @Value("${security.access-jwt.expiration}")
  private long EXPIRATION; // em milissegundos

  public String generateToken(UserEntity user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", user.getUsername());
    claims.put("email", user.getEmail());
    claims.put("role", user.getRole().name());
    return buildToken(claims, user.getId().toString());
  }

  private String buildToken(Map<String, Object> claims, String subject) {
    Instant now = Instant.now();
    Instant exp = now.plusMillis(EXPIRATION);

    return Jwts.builder()
        .claims(claims)
        .subject(subject)
        .issuedAt(Date.from(now))
        .expiration(Date.from(exp))
        .signWith(getSignKey(), Jwts.SIG.HS256)
        .compact();
  }

  private SecretKey getSignKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
    final Claims claims = extractAllClaims(token);
    return claimResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    try {
      return parseAndVerifyToken(token);
    } catch (io.jsonwebtoken.JwtException e) {
      throw new IllegalArgumentException("Invalid JWT token", e);
    }
  }

  private Claims parseAndVerifyToken(String token) {
    return Jwts.parser()
        .verifyWith(getSignKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public String extractEmail(String token) {
    return extractClaim(token, claims -> claims.get("email", String.class));
  }

  public String extractRole(String token) {
    return extractClaim(token, claims -> claims.get("role", String.class));
  }

  public String extractUsername(String token) {
    return extractClaim(token, claims -> claims.get("username", String.class));
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public Boolean isTokenValid(String token, UserDetails userDetails) {
    // 1. Verifica se o token está expirado
    if (isTokenExpired(token)) {
      return false;
    }

    // 2. Verifica se a role corresponde
    final String tokenRole = extractRole(token);
    boolean hasRole =
        userDetails.getAuthorities().stream()
            .anyMatch(
                authority ->
                    authority.getAuthority().equals("ROLE_" + tokenRole)
                        || authority.getAuthority().equals(tokenRole));
    if (!hasRole) {
      return false;
    }

    // 3. Verifica se o email corresponde
    final String email = extractEmail(token);
    return email.equals(userDetails.getUsername());
  }
}
