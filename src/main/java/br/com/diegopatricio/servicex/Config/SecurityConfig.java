/*package br.com.diegopatricio.servicex.Config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
                .withUser("Diego")
                .password(passwordEncoder.encode("12345"))
                .roles("USER")
                .and()
                .withUser("Patricio")
                .password(passwordEncoder.encode("987654"))
                .roles("USER", "ADMIN");;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Configuration
    public static class WebSecurityConfig {

        @Autowired
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .requestMatchers(HttpMethod.GET, "/categorias/**").permitAll()
                    .requestMatchers(HttpMethod.POST, "/categorias").hasRole("USER")
                    .anyRequest()
                    .authenticated()
                    .and()
                    .csrf().disable()
                    .httpBasic();
        }
    }
}*/