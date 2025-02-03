package com.lightswitch.infrastructure.database.repository

import com.lightswitch.infrastructure.database.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long>{
    fun existsByUsername(username: String): Boolean
    fun findByUsername(username: String): User?
}
