package com.lightswitch.infrastructure.database.repository

import com.lightswitch.infrastructure.database.entity.RefreshToken
import org.springframework.data.jpa.repository.JpaRepository

interface RefreshTokenRepository: JpaRepository<RefreshToken, Long>