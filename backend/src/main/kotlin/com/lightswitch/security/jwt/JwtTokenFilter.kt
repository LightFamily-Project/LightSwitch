package com.lightswitch.security.jwt

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException

@Component
class JwtTokenFilter(private val jwtTokenProvider: JwtTokenProvider) : OncePerRequestFilter() {

    private val HEADER_STRING = "Authorization"
    private val TOKEN_PREFIX = "Bearer "

    @Throws(ServletException::class, IOException::class)
    public override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        getTokenFromRequest(request)
            ?.takeIf { jwtTokenProvider.validateToken(it) }
            ?.let { jwtTokenProvider.getAuthentication(it) }
            ?.also { SecurityContextHolder.getContext().authentication = it }

        filterChain.doFilter(request, response)
    }

    private fun getTokenFromRequest(request: HttpServletRequest): String? {
        return request.getHeader(HEADER_STRING)
            ?.takeIf { it.startsWith(TOKEN_PREFIX) }
            ?.removePrefix(TOKEN_PREFIX)
    }
}