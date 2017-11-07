package com.bishop.malo.authentication.configs;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * provide a ResourceServerConfigurerAdapter bean
 * enables a Spring Security filter that authenticates requests via an incoming OAuth2 token
 * @author mlecam
 *
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	@Value("${security.oauth2.resource.id}")
	private String resourceId;

    // The DefaultTokenServices bean provided at the AuthorizationConfig
    @Autowired
    private DefaultTokenServices tokenServices;

    // The TokenStore bean provided at the AuthorizationConfig
    @Autowired
    private TokenStore tokenStore;
	
    
    // To allow the rResourceServerConfigurerAdapter to understand the token,
    // it must share the same characteristics with AuthorizationServerConfigurerAdapter.
    // So, we must wire it up the beans in the ResourceServerSecurityConfigurer.
	/**
	 * wire it up the beans in the ResourceServerSecurityConfigurer.
	 */
    @Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		 resources
         .resourceId(resourceId)
         .tokenServices(tokenServices)
         .tokenStore(tokenStore);
	}
	
	/**
	 * Control the access to specific resources.
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatcher(new OAuthRequestedMatcher())
		.csrf().disable()
		.anonymous().disable()
		.authorizeRequests()
		.antMatchers(HttpMethod.OPTIONS).permitAll()
		// when restricting access to 'Roles' you must remove the "ROLE_" part role
        // for "ROLE_USER" use only "USER"
        .antMatchers("/api/hello").access("hasAnyRole('USER')")          
        .antMatchers("/api/admin").hasRole("ADMIN")
        // restricting all access to /api/** to authenticated users
        .antMatchers("/api/**").authenticated();
	}

	/**
	 * OAuthRequestedMatcher 
	 */
	private static class OAuthRequestedMatcher implements RequestMatcher {
		public boolean matches(HttpServletRequest request) {
			String auth = request.getHeader("Authorization");
			// Determine if the client request contained an OAuth Authorization
			boolean haveOauth2Token = (auth != null) && auth.startsWith("Bearer");
			boolean haveAccessToken = request.getParameter("access_token")!=null;
			boolean isApi = false;
			
			// Determine if the resource called is "/api/**"
	        String path = request.getServletPath();
	        if ( path.length() >= 5 ) {
	          path = path.substring(0, 5);
	          isApi = path.equals("/api/");
	        } else isApi = false;
			
			return isApi;
		}
	}
}
