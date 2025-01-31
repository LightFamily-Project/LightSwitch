package com.lightswitch.security.jwt

import org.springframework.stereotype.Component
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import jakarta.annotation.PostConstruct
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import java.security.SecureRandom
import java.util.*

@Component
class JwtTokenProvider( @Value("\${jwt.secret}") private var secretKey: String) {

    private val tokenValidTime = 86400000 //24 hrs

    @PostConstruct
    protected fun init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.toByteArray())
    }

    fun createToken(authentication: Authentication): String {
        return Jwts.builder()
            .setSubject(authentication.name)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + tokenValidTime))
            .signWith(SignatureAlgorithm.HS512, secretKey.toByteArray())
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            val claims = Jwts.parserBuilder()
                .setSigningKey(secretKey.toByteArray())
                .build()
                .parseClaimsJws(token)
            !claims.body.expiration.before(Date())
        } catch (e: Exception) {
            false
        }
    }

    fun getAuthentication(token: String): Authentication {
        val userName = getUserNameFromToken(token)
        return UsernamePasswordAuthenticationToken(userName, null, ArrayList())
    }

    fun getUserNameFromToken(token: String): String {
        return Jwts.parserBuilder()
            .setSigningKey(secretKey.toByteArray())
            .build()
            .parseClaimsJws(token)
            .body
            .subject
    }
}