package com.example;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AuthApplication.class)
@WebAppConfiguration
@ActiveProfiles("test")
@IntegrationTest("server.port=0")
public class AuthApplicationTests {

	@Value("${local.server.port}")
	private int port;

	@Autowired
	@Qualifier("defaultAuthorizationServerTokenServices")
	private DefaultTokenServices tokenServices;

	@Test
	public void tokenStoreIsJwt() {
		assertTrue("Wrong token store type: " + tokenServices,
				ReflectionTestUtils.getField(tokenServices, "tokenStore") instanceof JwtTokenStore);
	}

	@Test
	public void tokenKeyEndpointUnprotected() {
		assertEquals(HttpStatus.OK,
				new TestRestTemplate().getForEntity("http://localhost:" + port + "/oauth/token_key", String.class)
						.getStatusCode());
	}

}
