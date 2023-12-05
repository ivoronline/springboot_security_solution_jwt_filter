package com.example.springboot_security_solution_jwt_filter.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@RestController
public class JWTController {

  //PROPERTIES
  @Autowired JWTUtil               jwtUtil;
  @Autowired AuthenticationManager authenticationManager;

  //==================================================================
  // CREATE JWT
  //==================================================================
  @RequestMapping("CreateJWT")
  String createJWT(@RequestParam String username, @RequestParam String password) throws IOException {

    //AUTHENTICATE (COMPARE ENTERED & STORED PASSWORD)
    Authentication inputAuthentication  = new UsernamePasswordAuthenticationToken(username, password);
    Authentication outputAuthentication = authenticationManager.authenticate(inputAuthentication); //Exception

    //CREATE JWT
    String authorities = outputAuthentication.getAuthorities().toString(); //"[ROLE_ADMIN, ROLE_USER]"
    String jwt         = jwtUtil.createJWT(username, authorities);

    //RETURN JWT
    return jwt;

  }

  //==================================================================
  // EXCEPTION HANDLER                             (For all Endpoints)
  //==================================================================
  @ExceptionHandler
  String exceptionHandler(Exception exception) {
    return exception.getMessage(); //Bad credentials
  }

}


