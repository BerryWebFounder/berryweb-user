package com.berryweb.user.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         org.springframework.security.core.AuthenticationException ex) throws IOException {
        log.error("Responding with unauthorized error. Message - {}", ex.getMessage());
        httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), "Unauthorized");
    }

}
