package org.codewithanish.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class CustomClaimsConfig {

    @Autowired
    private HttpServletRequest request;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims(claims ->
                {
                    claims.put("user-name", request.getHeader("UserName"));
                    claims.put("user-id", request.getHeader("UserId"));
                    claims.put("user-provider", request.getHeader("UserProvider"));
                    claims.put("authorities", request.getHeader("UserRole") != null ?
                            Arrays.stream(request.getHeader("UserRole").split("\\s*,\\s*")).toList() :
                            Collections.emptyList());
                });
            }
        });
    }
}
