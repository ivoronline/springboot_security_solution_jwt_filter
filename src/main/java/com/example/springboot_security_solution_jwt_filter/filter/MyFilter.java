package com.example.springboot_security_solution_jwt_filter.filter;

import com.example.springboot_security_solution_jwt_filter.jwt.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Order(1)
@Component
public class MyFilter extends OncePerRequestFilter {

  //PROPERTIES
  @Autowired JWTUtil jwtUtil;

  //DO FILTER INTERNAL
  @Override
  public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    throws IOException, ServletException {

    //GET AUTHORIZATION HEADER
    String authorization = request.getHeader("Authorization");

    //CREATE AUTHENTICATION OBJECT
    if(authorization != null){
      String         jwt            = jwtUtil.getJWTFromAuthorizationHeader(authorization);
      Authentication authentication = jwtUtil.createAuthenticationObjectFromJWT(jwt);
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    //CALL NEXT FILTER
    chain.doFilter(request, response);

  }

}

