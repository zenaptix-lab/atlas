package org.apache.atlas.web.security;

import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public interface SecurityConfigurerAdapter extends WebSecurityConfigurerAdapter, KeycloakWebSecurityConfigurerAdapter {

}