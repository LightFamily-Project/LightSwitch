package com.lightswitch.security.jwt

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder

class JwtTokenFilterTest {

    @Mock
    private lateinit var jwtTokenProvider: JwtTokenProvider

    @Mock
    private lateinit var request: HttpServletRequest

    @Mock
    private lateinit var response: HttpServletResponse

    @Mock
    private lateinit var filterChain: FilterChain

    private lateinit var jwtTokenFilter: JwtTokenFilter

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        jwtTokenFilter = JwtTokenFilter(jwtTokenProvider)
    }

    @Test
    fun `should set authentication if token is valid`() {
        val validToken = "validToken"
        val authentication = UsernamePasswordAuthenticationToken("user", null, emptyList())
        Mockito.`when`(request.getHeader("Authorization")).thenReturn("Bearer $validToken")
        Mockito.`when`(jwtTokenProvider.validateToken(validToken)).thenReturn(true)
        Mockito.`when`(jwtTokenProvider.getAuthentication(validToken)).thenReturn(authentication)

        jwtTokenFilter.doFilterInternal(request, response, filterChain)

        val context: SecurityContext = SecurityContextHolder.getContext()
        assert(context.authentication == authentication)
        Mockito.verify(filterChain).doFilter(request, response)
    }

    @Test
    fun `should not set authentication if token is invalid`() {
        val invalidToken = "invalidToken"
        Mockito.`when`(request.getHeader("Authorization")).thenReturn("Bearer $invalidToken")
        Mockito.`when`(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false)

        jwtTokenFilter.doFilterInternal(request, response, filterChain)

        val context: SecurityContext = SecurityContextHolder.getContext()
        assert(context.authentication == null)
        Mockito.verify(filterChain).doFilter(request, response)
    }

    @Test
    fun `should not set authentication if no token is provided`() {
        Mockito.`when`(request.getHeader("Authorization")).thenReturn(null)

        jwtTokenFilter.doFilterInternal(request, response, filterChain)

        val context: SecurityContext = SecurityContextHolder.getContext()
        assert(context.authentication == null)
        Mockito.verify(filterChain).doFilter(request, response)
    }
}
