package com.frankmoley.lil.adminweb.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .antMatchers("/customers/**").hasRole("USER")
                .antMatchers("/orders/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .failureUrl("/login?error")
                .permitAll()
                .and()
                .logout()
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .logoutSuccessUrl("/login?logout")
                .permitAll();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public  PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public GrantedAuthoritiesMapper authoritiesMapper() {
        SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        authorityMapper.setConvertToUpperCase(true);
        return authorityMapper;
    }
}
