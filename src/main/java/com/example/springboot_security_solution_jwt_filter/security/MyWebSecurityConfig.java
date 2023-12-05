package com.example.springboot_security_solution_jwt_filter.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {

  //========================================================================
  // CONFIGURE
  //========================================================================
  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity.formLogin();
    httpSecurity.authorizeRequests().antMatchers("/GetJWT", "/Authenticate").permitAll(); //Anonymous access
    httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //For filter
  }

  //========================================================================
  // PASSWORD ENCODER
  //========================================================================
  @Bean
  PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  //========================================================================
  // AUTHENTICATION MANAGER BEAN                             (For CreateJWT)
  //========================================================================
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  //========================================================================
  // USER DETAILS SERVICE BEAN
  //========================================================================
  @Bean
  @Override
  public UserDetailsService userDetailsServiceBean() throws Exception {

    //CREATE USERS
    UserDetails myuser= User.withUsername("myuser").password("myuserpassword").roles("USER","ADMIN").build();

    //LOAD USERS
    return new InMemoryUserDetailsManager(myuser);

  }

}
