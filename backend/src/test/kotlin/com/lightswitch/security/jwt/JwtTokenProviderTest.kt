package com.lightswitch.security.jwt

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import java.security.SecureRandom
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JwtTokenProviderTest {

    private lateinit var jwtTokenProvider: JwtTokenProvider
    private lateinit var mockAuthentication: Authentication

    private val username = "testUser"
    private val password = "password123"

    @BeforeEach
    fun setUp() {
        jwtTokenProvider = JwtTokenProvider(secretKey = generateSecretKey())
        mockAuthentication = UsernamePasswordAuthenticationToken(username, password)
    }

    fun generateSecretKey(): String {
        val secureRandom = SecureRandom()
        val secretKeyBytes = ByteArray(512)
        secureRandom.nextBytes(secretKeyBytes)
        return Base64.getEncoder().encodeToString(secretKeyBytes)
    }

    @Test
    fun `should create valid JWT token`() {
        val token = jwtTokenProvider.createToken(mockAuthentication)

        assert(token.isNotEmpty())

        val extractedUsername = jwtTokenProvider.getUserNameFromToken(token)
        assertEquals(username, extractedUsername)
    }

    @Test
    fun `should validate valid token`() {
        val token = jwtTokenProvider.createToken(mockAuthentication)
        assertTrue(jwtTokenProvider.validateToken(token))
    }

    @Test
    fun `should return false for invalid token`() {
        val invalidToken = "invalid.jwt.token"
        assertFalse(jwtTokenProvider.validateToken(invalidToken))
    }

    @Test
    fun `should extract authentication from token`() {
        val token = jwtTokenProvider.createToken(mockAuthentication)
        val authentication = jwtTokenProvider.getAuthentication(token)
        assertEquals(username, authentication.name)
    }
}
