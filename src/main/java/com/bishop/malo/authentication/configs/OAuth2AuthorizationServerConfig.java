package com.bishop.malo.authentication.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

/**
 * provide a AuthorizationServerConfigurerAdapter bean to correctly setup the authorization server.
 * @author mlecam
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	/**
	 * token validity in seconds.
	 */
	private int accessTokenValiditySeconds = 10000;
	
	/**
	 * token refresh validity in seconds.
	 */
	private int refreshTokenValiditySeconds = 30000;

	
	/**
	 * AuthenticationManager Bean.
	 */
	@Autowired
	private AuthenticationManager authenticationManager;

	@Value("${security.oauth2.resource.id}")
	private String resourceId;

	@Value("mypass")
	private String signingKey;

	/**
	 * Configure the non-security features of the Authorization Server endpoints,
	 * like token store, token customizations, user approvals and grant types.
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
				.authenticationManager(this.authenticationManager)
				.tokenServices(tokenServices())
				.tokenStore(tokenStore())
				.accessTokenConverter(accessTokenConverter());
	}
	
	/**
	 * Configure the security of the Authorization Server,
	 *  which means in practical terms the /oauth/token endpoint.
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		// allowing access to the token only for clients with 'ROLE_TRUSTED_CLIENT' authority
		oauthServer
				.tokenKeyAccess("hasAuthority('ROLE_TRUSTED_CLIENT')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
	}

	
	/**
	 * Configure the ClientDetailsService, declaring individual clients and their properties.
	 */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("trusted-app")
                    .authorizedGrantTypes("client_credentials", "password", "refresh_token")
                    .authorities("ROLE_TRUSTED_CLIENT")
                    .scopes("read", "write")
                    .resourceIds(resourceId)
                    .accessTokenValiditySeconds(accessTokenValiditySeconds)
                    .refreshTokenValiditySeconds(refreshTokenValiditySeconds)
                    .secret("secret");
        
        // TODO: Write a proper clientDetailsServiceConfig.
    }


	/**
	 * 
	 * @return TokenStore
	 */
	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	/**
	 * give the JWT acces token converter with our secret key configured for the private attribute signingkey.
	 * run into /src/main/resources/ : keytool -genkeypair -alias mykeys -keyalg RSA -keypass mypass -keystore mykeys.jks -storepass mypass
	 * @return JwtAccessTokenConverter
	 */
	
	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
	    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
	    KeyStoreKeyFactory keyStoreKeyFactory =
	            new KeyStoreKeyFactory(
	                    new ClassPathResource("mykeys.jks"),
	                    signingKey.toCharArray());
	    converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mykeys"));
	    return converter;
	}
	

	/**
	 * 
	 * @return DefaultTokenServices
	 */
	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		defaultTokenServices.setTokenEnhancer(accessTokenConverter());
		return defaultTokenServices;
	}
}