package proxy;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.cloud.sleuth.Sampler;
import org.springframework.cloud.sleuth.sampler.AlwaysSampler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;


@SpringBootApplication
@EnableZuulProxy
@RestController
@EnableRedisHttpSession
@EnableAspectJAutoProxy(proxyTargetClass=true)
@EnableAsync
public class ProxyApplication {

	@Bean
	public Sampler<?> defaultSampler() {
		return new AlwaysSampler();
	}

	@RequestMapping("/user")
	@ResponseBody
	public Map<String, Object> user(Principal user) {
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("name", user.getName());
		map.put("roles", AuthorityUtils.authorityListToSet(((Authentication) user)
				.getAuthorities()));
		return map;
	}

	@RequestMapping("/login")
	public String login() {
		return "forward:/";
	}

	public static void main(String[] args) {
		SpringApplication.run(ProxyApplication.class, args);
	}

}

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class WorkaroundRestTemplateCustomizer implements UserInfoRestTemplateCustomizer {

	@Override
	public void customize(OAuth2RestTemplate template) {
		template.setInterceptors(new ArrayList<>(template.getInterceptors()));
	}
	
}

@Component
class LoginWebMvcConfigurerAdapter extends WebMvcConfigurerAdapter {

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
	}
	
}
