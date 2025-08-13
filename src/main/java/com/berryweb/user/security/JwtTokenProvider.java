package com.berryweb.user.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400000}") // 24시간 기본값
    private long jwtExpiration;

    public String createToken(Long userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    // 기존 호환성을 위한 generateToken 메서드
    public String generateToken(Object userPrincipal) {
        Long userId = extractUserIdFromPrincipal(userPrincipal);
        return createToken(userId);
    }

    // UserPrincipal에서 userId 추출하는 헬퍼 메서드
    private Long extractUserIdFromPrincipal(Object userPrincipal) {
        if (userPrincipal == null) {
            throw new IllegalArgumentException("UserPrincipal cannot be null");
        }

        // CustomUserPrincipal 타입인 경우
        try {
            // 리플렉션을 사용해서 getId() 메서드 호출
            java.lang.reflect.Method getIdMethod = userPrincipal.getClass().getMethod("getId");
            Object idValue = getIdMethod.invoke(userPrincipal);

            if (idValue instanceof Long) {
                return (Long) idValue;
            } else if (idValue instanceof Number) {
                return ((Number) idValue).longValue();
            } else {
                return Long.parseLong(idValue.toString());
            }
        } catch (Exception e) {
            log.error("Failed to extract user ID from principal: {}", userPrincipal.getClass().getName(), e);
            throw new IllegalArgumentException("Cannot extract user ID from principal", e);
        }
    }

    // 토큰에서 사용자 ID 추출
    public Long getUserIdFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return Long.parseLong(claims.getSubject());
        } catch (Exception e) {
            log.error("Error extracting user ID from token", e);
            return null;
        }
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("JWT token validation error: {}", ex.getMessage());
        }
        return false;
    }

    // Signing Key 생성 - 일관된 방식 사용
    private SecretKey getSigningKey() {
        // 문자열을 바이트로 변환하여 사용 (Base64 디코딩 안함)
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 만료 시간 확인
    public Date getExpirationDateFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getExpiration();
        } catch (Exception e) {
            log.error("Error extracting expiration date from token", e);
            return null;
        }
    }

}
