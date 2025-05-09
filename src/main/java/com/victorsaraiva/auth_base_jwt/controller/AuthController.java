package com.victorsaraiva.auth_base_jwt.controller;

import com.victorsaraiva.auth_base_jwt.dtos.auth.LoginUserRequestDTO;
import com.victorsaraiva.auth_base_jwt.dtos.auth.SignupUserRequestDTO;
import com.victorsaraiva.auth_base_jwt.dtos.jwt.AccessTokenDTO;
import com.victorsaraiva.auth_base_jwt.dtos.jwt.CookieRefreshTokenDTO;
import com.victorsaraiva.auth_base_jwt.dtos.jwt.RefreshTokenDTO;
import com.victorsaraiva.auth_base_jwt.dtos.user.UserResponseDTO;
import com.victorsaraiva.auth_base_jwt.models.RefreshTokenEntity;
import com.victorsaraiva.auth_base_jwt.models.UserEntity;
import com.victorsaraiva.auth_base_jwt.security.CustomUserDetails;
import com.victorsaraiva.auth_base_jwt.services.AccessTokenService;
import com.victorsaraiva.auth_base_jwt.services.AuthService;
import com.victorsaraiva.auth_base_jwt.services.BlacklistService;
import com.victorsaraiva.auth_base_jwt.services.RefreshTokenService;
import jakarta.validation.Valid;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.base-url}/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final AccessTokenService accessTokenService;
  private final RefreshTokenService refreshTokenService;
  private final BlacklistService blacklistService;

  @PostMapping("/signup")
  public ResponseEntity<UserResponseDTO> signup(
      @Valid @RequestBody SignupUserRequestDTO signupUserRequestDTO) {
    UserResponseDTO registeredUser = this.authService.signup(signupUserRequestDTO);

    return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
  }

  @PostMapping("/login")
  public ResponseEntity<AccessTokenDTO> login(
      @Valid @RequestBody LoginUserRequestDTO loginUserRequestDTO) {

    // Extrai o usuario do request
    UserEntity userEntity = authService.login(loginUserRequestDTO);

    // Gera novos tokens e configura a resposta com cookies
    return generateTokensResponse(userEntity);
  }

  @PostMapping("/refreshToken")
  public ResponseEntity<AccessTokenDTO> refreshToken(
      @CookieValue("refreshToken") String oldRefreshToken,
      @CookieValue("refreshTokenId") Long oldRefreshTokenId) {

    // Valida o refreshToken
    RefreshTokenEntity oldRt =
        refreshTokenService.validateRefreshToken(oldRefreshTokenId, oldRefreshToken);

    // Estabelece quem é o usuario
    UserEntity user = oldRt.getUser();

    // Deleta o refreshToken usado
    refreshTokenService.deleteByRefreshTokenEntity(oldRt);

    // Gera novos tokens e configura a resposta com cookies
    return generateTokensResponse(user);
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @RequestHeader("Authorization") String authHeader,
      @CookieValue("refreshToken") String refreshToken,
      @CookieValue("refreshTokenId") Long refreshTokenId,
      @AuthenticationPrincipal CustomUserDetails userDetails) {

    String accessToken = authHeader.replace("Bearer ", "");
    UserEntity loggedUser = userDetails.user();

    // Extrai claims do access token
    String jti = accessTokenService.extractId(accessToken);
    Date exp = accessTokenService.extractExpiration(accessToken);

    // Adiciona o access token à blacklist
    blacklistService.blacklist(jti, exp.toInstant());

    // Deleta o refresh token
    refreshTokenService.deleteRefreshToken(refreshToken, refreshTokenId, loggedUser);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/ping")
  public String test() {
    return "Olá mundo";
  }

  private ResponseEntity<AccessTokenDTO> generateTokensResponse(UserEntity userEntity) {

    // Gera o accessToken
    String newAccessToken = accessTokenService.generateToken(userEntity);

    // Gera o refreshToken
    RefreshTokenDTO newRefreshToken = refreshTokenService.createRefreshToken(userEntity);

    // Gera o cookie do refreshToken
    CookieRefreshTokenDTO cookieRefreshTokenDTO = refreshTokenService.toCookie(newRefreshToken);

    // Retorna o novo accessToken e os cookies do refreshToken
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookieRefreshTokenDTO.tokenCookie().toString())
        .header(HttpHeaders.SET_COOKIE, cookieRefreshTokenDTO.idCookie().toString())
        .body(new AccessTokenDTO(newAccessToken));
  }
}
