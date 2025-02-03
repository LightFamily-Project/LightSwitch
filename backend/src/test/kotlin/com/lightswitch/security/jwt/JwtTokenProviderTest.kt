package com.lightswitch.security.jwt

import com.lightswitch.infrastructure.database.entity.User
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import java.util.*

class JwtTokenProviderTest {

    private lateinit var jwtTokenProvider: JwtTokenProvider
    private val secretKey =
        "64461f01e1af406da538b9c48d801ce59142452199ff112fb5404c8e7e98e3ff"
    val user = User(
        id = 1L,
        username = "testUser",
        passwordHash = "passwordHash",
        lastLoginAt = null
    )

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        jwtTokenProvider = JwtTokenProvider(secretKey)
    }

    @Test
    fun `generateJwtToken should return valid JWT token`() {
        val jwtToken = jwtTokenProvider.generateJwtToken(user.id!!, user)

        assertNotNull(jwtToken.accessToken)
        assertNotNull(jwtToken.refreshToken)
        assertTrue(jwtToken.accessTokenExpiredDate!! > 0)
    }

    @Test
    fun `generateJwtAccessToken should return only access token`() {
        val now = Date()
        val jwtToken = jwtTokenProvider.generateJwtAccessToken(user.id!!, user, now)

        assertNotNull(jwtToken.accessToken)
        assertNull(jwtToken.refreshToken)
        assertTrue(jwtToken.accessTokenExpiredDate!! > 0)
    }

    @Test
    fun `validateToken should return true for valid token`() {
        val jwtToken = jwtTokenProvider.generateJwtToken(user.id!!, user)

        val isValid = jwtTokenProvider.validateToken(jwtToken.accessToken!!)

        assertTrue(isValid)
    }

    @Test
    fun `validateToken should return false for expired token`() {
        val expiredToken = "invalidExpiredToken"

        val isValid = jwtTokenProvider.validateToken(expiredToken)

        assertFalse(isValid)
    }

    @Test
    fun `getAuthentication should return valid authentication object`() {
        val jwtToken = jwtTokenProvider.generateJwtToken(user.id!!, user)

        val authentication = jwtTokenProvider.getAuthentication(jwtToken.accessToken!!)

        assertNotNull(authentication)
        assertEquals(user.id.toString(), authentication.name)
    }

    @Test
    fun `getRefreshTokenSubject should return correct user ID for refresh token`() {
        val jwtToken = jwtTokenProvider.generateJwtToken(user.id!!, user)

        val refreshTokenSubject = jwtTokenProvider.getRefreshTokenSubject(jwtToken.refreshToken!!)

        assertEquals(user.id, refreshTokenSubject)
    }

    @Test
    fun `refreshTokenPeriodCheck should return true if refresh token expired more than 3 days`() {
        val now = Date()
        val issuedTime = Date(now.time - 5 * 24 * 60 * 60 * 1000L)
        val expiredTime = Date(now.time + 4 * 24 * 60 * 60 * 1000L)

        val refreshToken = Jwts.builder()
            .setSubject("1")
            .setIssuedAt(issuedTime)
            .setExpiration(expiredTime)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)), SignatureAlgorithm.HS256)
            .compact()

        val result = jwtTokenProvider.isRefreshTokenRenewalRequired(refreshToken)

        assertTrue(result)
    }

    @Test
    fun `refreshTokenPeriodCheck should return false if refresh token expired less than 3 days`() {
        val now = Date()
        val issuedTime = Date(now.time - 5 * 24 * 60 * 60 * 1000L)
        val expiredTime = Date(now.time + 2 * 24 * 60 * 60 * 1000L)

        val refreshToken = Jwts.builder()
            .setSubject("1")
            .setIssuedAt(issuedTime)
            .setExpiration(expiredTime)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)), SignatureAlgorithm.HS256)
            .compact()

        val result = jwtTokenProvider.isRefreshTokenRenewalRequired(refreshToken)

        assertFalse(result)
    }

}
