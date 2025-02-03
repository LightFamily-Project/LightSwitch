package com.lightswitch.security.jwt

import com.lightswitch.infrastructure.database.entity.User
import io.jsonwebtoken.*
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey


@Component
class JwtTokenProvider(@Value("\${jwt.secret}") private var secretKey: String) {

    private val logger: Logger = LoggerFactory.getLogger(JwtTokenProvider::class.java)
    private val TYPE = "tokenType"
    private val USER = "user"
    private val accessValidTime = 30 * 60 * 1000L // 30 minutes
    private val refreshValidTime = 7 * 24 * 60 * 60 * 1000L // 7 days
    private val threeDays = 3 * 24 * 60 * 60 * 1000L // 3 days

    fun generateJwtToken(userId: Long, user: User): JwtToken {

        val now = Date()
        val accessToken = createAccessToken(userId, user, now)

        val refreshTokenClaims: Claims = Jwts.claims().setSubject(userId.toString()).apply {
            this[TYPE] = "refresh"
        }
        val refreshToken = Jwts.builder()
            .setClaims(refreshTokenClaims)
            .setIssuedAt(now)
            .setExpiration(Date(now.time + refreshValidTime))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact()

        return JwtToken(
            accessToken = accessToken,
            refreshToken = refreshToken,
            accessTokenExpiredDate = accessValidTime
        )
    }

    private fun createAccessToken(
        userId: Long,
        user: User,
        now: Date
    ): String? {
        val accessTokenClaims: Claims = Jwts.claims().setSubject(userId.toString()).apply {
            this[TYPE] = "access"
            this[USER] = userToMap(user)
        }

        val accessToken = Jwts.builder()
            .setClaims(accessTokenClaims)
            .setIssuedAt(now)
            .setExpiration(Date(now.time + accessValidTime))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact()
        return accessToken
    }


    private fun userToMap(user: User): Map<String, Any> {
        val userMap: MutableMap<String, Any> = HashMap()

        userMap["userId"] = user.id.toString()
        userMap["userName"] = user.username
        userMap["lat"] = user.lastLoginAt.toString()

        return userMap
    }


    private fun getSigningKey(): SecretKey? {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey))
    }

    fun generateJwtAccessToken(userId: Long, user: User, now: Date): JwtToken {
        val accessToken = createAccessToken(userId, user, now)
        return JwtToken(
            accessToken = accessToken,
            refreshToken = null,
            accessTokenExpiredDate = accessValidTime
        )
    }

    fun validateToken(token: String): Boolean {
        return try {
            val claims = parseClaims(token)
            !claims.expiration.before(Date())
        } catch (e: Exception) {
            false
        }
    }

    fun getAuthentication(token: String): Authentication {
        val claims = parseClaims(token)
        val userName = claims.subject
        return UsernamePasswordAuthenticationToken(userName, token, ArrayList())
    }

    private fun parseClaims(token: String): Claims {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .body
        } catch (e: SecurityException) {
            logger.error("Invalid JWT signature -> Message: ${e.message}")
            throw JwtException(e.message)
        } catch (e: MalformedJwtException) {
            logger.error("Invalid JWT token -> Message: ${e.message}")
            throw JwtException(e.message)
        } catch (e: ExpiredJwtException) {
            logger.error("Expired JWT token -> Message: ${e.message}")
            throw JwtException(e.message)
        } catch (e: UnsupportedJwtException) {
            logger.error("Unsupported JWT token -> Message: ${e.message}")
            throw JwtException(e.message)
        } catch (e: IllegalArgumentException) {
            logger.error("JWT token compact of handler are invalid -> Message: ${e.message}")
            throw JwtException(e.message)
        }
    }


    fun getRefreshTokenSubject(token: String): Long {
        return try {
            val claims = parseClaims(token)
            if (claims[TYPE] != "refresh")
                throw RuntimeException("Token is not refresh token")

            claims.subject.toLong()
        } catch (e: Exception) {
            throw RuntimeException("Invalid token")
        }
    }

    fun isRefreshTokenRenewalRequired(token: String?): Boolean {
        val claimsJws =
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token)
        val now = (Date()).time
        val refreshExpiredTime = claimsJws.body.expiration.time

        return refreshExpiredTime - now > threeDays
    }

}