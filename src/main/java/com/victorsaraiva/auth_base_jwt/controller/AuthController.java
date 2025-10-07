package com.victorsaraiva.auth_base_jwt.controller;

import com.victorsaraiva.auth_base_jwt.dtos.auth.LoginRequestDTO;
import com.victorsaraiva.auth_base_jwt.dtos.auth.SignupRequestDTO;
import com.victorsaraiva.auth_base_jwt.dtos.jwt.AccessTokenDTO;
import com.victorsaraiva.auth_base_jwt.dtos.user.UserDTO;
import com.victorsaraiva.auth_base_jwt.models.UserEntity;
import com.victorsaraiva.auth_base_jwt.security.CustomUserDetails;
import com.victorsaraiva.auth_base_jwt.services.AuthService;
import com.victorsaraiva.auth_base_jwt.services.security.BlacklistService;
import com.victorsaraiva.auth_base_jwt.services.security.RefreshTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.base-url}/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final RefreshTokenService refreshTokenService;
  private final BlacklistService blacklistService;

  @PostMapping("/signup")
  public ResponseEntity<UserDTO> signup(@Valid @RequestBody SignupRequestDTO signupRequestDTO) {
    UserDTO registeredUser = this.authService.signup(signupRequestDTO);

    return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
  }

  @PostMapping("/login")
  public ResponseEntity<AccessTokenDTO> login(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {

    // Extrai o usuario do request
    UserEntity userEntity = authService.login(loginRequestDTO);

    // Gera novos tokens e configura a resposta com cookies
    return refreshTokenService.generateJwtTokensResponse(userEntity);
  }

  @PostMapping("/refresh-token")
  public ResponseEntity<AccessTokenDTO> refreshToken(
      @CookieValue("refreshToken") String oldRefreshToken,
      @CookieValue("refreshTokenId") Long oldRefreshTokenId) {

    return refreshTokenService.refreshToken(oldRefreshToken, oldRefreshTokenId);
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @RequestHeader("Authorization") String authHeader,
      @CookieValue("refreshToken") String refreshToken,
      @CookieValue("refreshTokenId") Long refreshTokenId,
      @AuthenticationPrincipal CustomUserDetails userDetails) {

    // Adiciona o access token à blacklist
    blacklistService.blacklistByAuthHeader(authHeader);

    // Deleta o refresh token
    refreshTokenService.deleteRefreshToken(
        refreshToken, refreshTokenId, userDetails.user().getId());
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/ping")
  public ResponseEntity<String> ping() {
    return ResponseEntity.ok("pong");
  }
}
