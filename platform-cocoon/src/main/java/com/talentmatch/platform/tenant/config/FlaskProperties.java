package com.talentmatch.platform.tenant.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "flask")
public class FlaskProperties {
	
	private String baseUrl;

}
