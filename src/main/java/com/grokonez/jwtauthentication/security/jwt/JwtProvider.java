package com.grokonez.jwtauthentication.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.grokonez.jwtauthentication.security.services.UserPrinciple;

import java.util.Date;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    //Recupera a secret key do application.properties
    @Value("${grokonez.app.jwtSecret}")
    private String jwtSecret;

    //recupera o expiration time do application.properties
    @Value("${grokonez.app.jwtExpiration}")
    private int jwtExpiration;

    //método para gerar o token
    public String generateJwtToken(Authentication authentication) {

    	//monta o objeto UserPrinciple para encapsulmento no objeto de authentication
        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        //retorna o token com o username, data de geração, data de expiração, secret key do application.properties 
        return Jwts.builder()
		                .setSubject((userPrincipal.getUsername()))
		                .setIssuedAt(new Date())
		                .setExpiration(new Date((new Date()).getTime() + jwtExpiration*1000))
		                .signWith(SignatureAlgorithm.HS512, jwtSecret)
		                .compact();
    }
    
    //validao token
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }
        
        return false;
    }
    
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
			                .setSigningKey(jwtSecret)
			                .parseClaimsJws(token)
			                .getBody().getSubject();
    }
}