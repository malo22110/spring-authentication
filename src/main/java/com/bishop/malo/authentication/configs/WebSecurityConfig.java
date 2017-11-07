package com.bishop.malo.authentication.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bishop.malo.authentication.services.MyUserDetailsService;

/**
 * provide a  WebSecurityConfigurerAdapter Bean that will give us the base to configure the authentication process.
 * @author mlecam
 */
@Configuration
@EnableWebSecurity
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	// user Service to handle authentication
	/**
	 * UserDetailsService is a core interface which loads user-specific data.
	 */
	@Autowired
	protected MyUserDetailsService userDetailsService;

	/**
	 * The place to configure the authenticationManager Bean.
	 * @param AuthenticationManagerBuilder
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
		auth.authenticationProvider(authProvider());
	}	


	/**
	 *  configuring web-based security for specific http requests.
	 *  @param HttpSecurity 
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.formLogin().disable() // disable form authentication
	        .anonymous().disable() // disable anonymous user
	        .httpBasic().and()
	        // restricting access to authenticated users
	        .authorizeRequests().anyRequest().authenticated();
	}

	/**
	 * provides the default AuthenticationManager as a Bean.
	 * @return AuthenticationManager 
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	
	/**
	 * authenticationProvider that use our userDetailsService and passwordEncoder Beans.
	 * @return
	 */
	@Bean
	public DaoAuthenticationProvider authProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	// type of the password encoding
	/**
	 * our password encoder that give our encoding strategy.
	 * @return PasswordEncoder
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
