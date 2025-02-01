package com.lightswitch.security

import com.lightswitch.exception.BusinessException
import com.lightswitch.infrastructure.database.entity.RefreshToken
import com.lightswitch.infrastructure.database.entity.User
import com.lightswitch.infrastructure.database.repository.RefreshTokenRepository
import com.lightswitch.infrastructure.database.repository.UserRepository
import com.lightswitch.security.jwt.JwtToken
import com.lightswitch.security.jwt.JwtTokenProvider
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime
import java.util.*

@Service
class AuthService(
    private val jwtTokenProvider: JwtTokenProvider,
    val userRepository: UserRepository,
    val refreshTokenRepository: RefreshTokenRepository,
    val passwordEncoder: PasswordEncoder
) {

    @Transactional
    fun login(username: String, password: String): JwtToken {
        val user = userRepository.findByUsername(username).orElseThrow {
            throw BusinessException("User with username $username not found")
        }

        if (!passwordEncoder.matches(password, user.passwordHash)) {
            throw BusinessException("Password is incorrect")
        }

        user.lastLoginAt = LocalDateTime.now()
        userRepository.save(user)
        return jwtTokenProvider.generateJwtToken(user.id!!, user)
    }

    @Transactional
    fun signup(username: String, password: String): User {
        if (userRepository.existsByUsername(username)) {
            throw BusinessException("Username already exists")
        }
        val passwordHash = passwordEncoder.encode(password)

        val newUser = User(
            username = username,
            passwordHash = passwordHash
        )
        return userRepository.save(newUser)
    }

    @Transactional
    fun reissue(jwtToken: JwtToken): JwtToken? {
        if (!jwtTokenProvider.validateToken(jwtToken.refreshToken!!)) {
            throw BusinessException("Refresh Token is Not Valid")
        }

        val userId: Long = jwtTokenProvider.getRefreshTokenSubject(jwtToken.refreshToken)
        val refreshToken: RefreshToken = refreshTokenRepository.findById(userId)
            .orElseThrow { BusinessException("Log-out user") }

        if (refreshToken.value != jwtToken.refreshToken) {
            throw BusinessException("Refresh Token is Not Valid")
        }

        val newToken: JwtToken?
        val user = userRepository.findById(userId)
            .orElseThrow { BusinessException("User not found") }

        if (jwtTokenProvider.isRefreshTokenRenewalRequired(refreshToken.value)) {
            // Refresh Token의 유효기간이 3일 미만일 경우 전체(Access / Refresh) 재발급
            newToken = jwtTokenProvider.generateJwtToken(userId, user)

            // Refresh Token 저장소 정보 업데이트
            refreshToken.value = newToken.refreshToken.toString()
            refreshTokenRepository.save(refreshToken)
        } else {
            // Refresh Token의 유효기간이 3일 이상일 경우 Access Token만 재발급
            newToken = jwtTokenProvider.generateJwtAccessToken(userId, user, Date())
        }

        return newToken
    }
}