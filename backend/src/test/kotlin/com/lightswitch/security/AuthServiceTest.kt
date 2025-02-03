package com.lightswitch.security

import com.lightswitch.exception.BusinessException
import com.lightswitch.infrastructure.database.entity.RefreshToken
import com.lightswitch.infrastructure.database.entity.User
import com.lightswitch.infrastructure.database.repository.RefreshTokenRepository
import com.lightswitch.infrastructure.database.repository.UserRepository
import com.lightswitch.security.jwt.JwtToken
import com.lightswitch.security.jwt.JwtTokenProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.LocalDateTime
import java.util.*

class AuthServiceTest {

    @Mock
    private lateinit var jwtTokenProvider: JwtTokenProvider

    @Mock
    private lateinit var userRepository: UserRepository

    @Mock
    private lateinit var refreshTokenRepository: RefreshTokenRepository

    @Mock
    private lateinit var passwordEncoder: PasswordEncoder

    private lateinit var authService: AuthService

    private val user = User(
        id = 1L,
        username = "testUser",
        passwordHash = "hashedPassword",
        lastLoginAt = LocalDateTime.now()
    )

    private val refreshToken = RefreshToken(
        userId = 1L,
        value = "refreshToken"
    )

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        authService = AuthService(
            jwtTokenProvider = jwtTokenProvider,
            userRepository = userRepository,
            refreshTokenRepository = refreshTokenRepository,
            passwordEncoder = passwordEncoder
        )
    }

    @Test
    fun `login should return JwtToken when credentials are correct`() {
        val username = "testUser"
        val password = "correctPassword"
        val jwtToken = JwtToken("accessToken", "refreshToken", 1800)

        Mockito.`when`(userRepository.findByUsername(username))
            .thenReturn(user)

        Mockito.`when`(passwordEncoder.matches(password, user.passwordHash))
            .thenReturn(true)

        Mockito.`when`(jwtTokenProvider.generateJwtToken(user.id!!, user))
            .thenReturn(jwtToken)

        val result = authService.login(username, password)

        assertNotNull(result)
        assertEquals(jwtToken.accessToken, result.accessToken)
        assertEquals(jwtToken.refreshToken, result.refreshToken)
    }

    @Test
    fun `login should throw BusinessException when user not found`() {
        val username = "invalidUser"
        val password = "somePassword"

        Mockito.`when`(userRepository.findByUsername(username))
            .thenReturn(null)

        val exception = assertThrows(BusinessException::class.java) {
            authService.login(username, password)
        }
        assertEquals("User with username invalidUser not found", exception.message)
    }

    @Test
    fun `login should throw BusinessException when password is incorrect`() {
        val username = "testUser"
        val password = "incorrectPassword"

        Mockito.`when`(userRepository.findByUsername(username))
            .thenReturn(user)

        Mockito.`when`(passwordEncoder.matches(password, user.passwordHash))
            .thenReturn(false)

        val exception = assertThrows(BusinessException::class.java) {
            authService.login(username, password)
        }
        assertEquals("Password is incorrect", exception.message)
    }

    @Test
    fun `signup should create a new user when username is not taken`() {
        val username = "newUser"
        val password = "newPassword"
        val passwordHash = "hashedPassword"
        val newUser = User(
            username = username,
            passwordHash = passwordHash
        )

        Mockito.`when`(userRepository.existsByUsername(username))
            .thenReturn(false)

        Mockito.`when`(passwordEncoder.encode(password))
            .thenReturn(passwordHash)

        Mockito.`when`(userRepository.save(ArgumentMatchers.any(User::class.java)))
            .thenReturn(newUser)

        val result = authService.signup(username, password)

        assertNotNull(result)
        assertEquals(username, result.username)
    }

    @Test
    fun `signup should throw BusinessException when username already exists`() {
        val username = "existingUser"
        val password = "somePassword"

        Mockito.`when`(userRepository.existsByUsername(username))
            .thenReturn(true)

        val exception = assertThrows(BusinessException::class.java) {
            authService.signup(username, password)
        }
        assertEquals("Username already exists", exception.message)
    }

    @Test
    fun `reissue should return new JwtToken if refresh token is valid and renewal is required`() {
        val userId = 1L
        val token = JwtToken("accessToken", "refreshToken", 1800)
        val newToken = JwtToken("newAccessToken", "newRefreshToken", 1800)
        val refreshTokenValue = "refreshToken"

        Mockito.`when`(jwtTokenProvider.validateToken(refreshTokenValue))
            .thenReturn(true)

        Mockito.`when`(jwtTokenProvider.getRefreshTokenSubject(refreshTokenValue))
            .thenReturn(userId)

        Mockito.`when`(refreshTokenRepository.findById(userId))
            .thenReturn(Optional.of(this.refreshToken))

        Mockito.`when`(userRepository.findById(userId))
            .thenReturn(Optional.of(user))

        Mockito.`when`(jwtTokenProvider.isRefreshTokenRenewalRequired(token.refreshToken))
            .thenReturn(true)

        Mockito.`when`(jwtTokenProvider.generateJwtToken(userId, user))
            .thenReturn(newToken)

        val result = authService.reissue(token)

        assertNotNull(result)
        assertEquals(newToken.accessToken, result?.accessToken)
        assertEquals(newToken.refreshToken, result?.refreshToken)
    }

    @Test
    fun `reissue should throw BusinessException if refresh token is invalid`() {
        val invalidRefreshToken = JwtToken("", "invalidToken", 1800)

        Mockito.`when`(jwtTokenProvider.validateToken(invalidRefreshToken.refreshToken!!))
            .thenReturn(false)

        val exception = assertThrows(BusinessException::class.java) {
            authService.reissue(invalidRefreshToken)
        }
        assertEquals("Refresh Token is Not Valid", exception.message)
    }

    @Test
    fun `reissue should return new JwtToken if refresh token is valid but no renewal is required`() {
        val userId = 1L
        val token = JwtToken("accessToken", "refreshToken", 1800)
        val newToken = JwtToken("newAccessToken", null, 1800)

        Mockito.`when`(jwtTokenProvider.validateToken(token.refreshToken!!))
            .thenReturn(true)

        Mockito.`when`(jwtTokenProvider.getRefreshTokenSubject(token.refreshToken!!))
            .thenReturn(userId)

        Mockito.`when`(refreshTokenRepository.findById(userId))
            .thenReturn(Optional.of(this.refreshToken))

        Mockito.`when`(userRepository.findById(userId))
            .thenReturn(Optional.of(user))

        Mockito.`when`(jwtTokenProvider.isRefreshTokenRenewalRequired(token.refreshToken))
            .thenReturn(false)

        Mockito.`when`(
            jwtTokenProvider.generateJwtAccessToken(
                eq(userId),
                eq(user),
                any()
            )
        )
            .thenReturn(newToken)

        val result = authService.reissue(token)

        assertNotNull(result)
        assertEquals(newToken.accessToken, result?.accessToken)
        assertNull(result?.refreshToken)
    }
}
