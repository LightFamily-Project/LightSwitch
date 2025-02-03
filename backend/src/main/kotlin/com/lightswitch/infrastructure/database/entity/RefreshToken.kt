package com.lightswitch.infrastructure.database.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id

@Entity
class RefreshToken (
    @Id
    @Column(nullable = false)
    val userId: Long,
    @Column(nullable = false)
    var value: String
): BaseEntity()