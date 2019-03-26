/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.atlas.web.security;

import org.apache.atlas.web.filters.ActiveServerFilter;
import org.apache.atlas.web.filters.AtlasAuthenticationEntryPoint;
import org.apache.atlas.web.filters.AtlasAuthenticationFilter;
import org.apache.atlas.web.filters.AtlasCSRFPreventionFilter;
import org.apache.atlas.web.filters.AtlasKnoxSSOAuthenticationFilter;
import org.apache.atlas.web.filters.StaleTransactionCleanupFilter;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.authentication.*;
import org.keycloak.adapters.springsecurity.filter.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;


import javax.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.util.LinkedHashMap;

import static org.apache.atlas.AtlasConstants.ATLAS_MIGRATION_MODE_FILENAME;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@KeycloakConfiguration
public class AtlasSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(AtlasSecurityConfig.class);

    private final AtlasAuthenticationProvider authenticationProvider;
    private final AtlasAuthenticationSuccessHandler successHandler;
    private final AtlasAuthenticationFailureHandler failureHandler;
    private final AtlasKnoxSSOAuthenticationFilter ssoAuthenticationFilter;
    private final AtlasAuthenticationFilter atlasAuthenticationFilter;
    private final AtlasCSRFPreventionFilter csrfPreventionFilter;
    private final AtlasAuthenticationEntryPoint atlasAuthenticationEntryPoint;

    //keycloak config
    private final AdapterDeploymentContextFactoryBean adapterDeploymentContext; //  (keycloak.json)
    private final KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint;
    private final KeycloakAuthenticationProvider keycloakAuthenticationProvider;
    private final KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter;
    private final KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter; // (authenticationManager)
    private final KeycloakLogoutHandler keycloakLogoutHandler;  // (adapterDeploymentContext)
    private final AntPathRequestMatcher logoutRequestMatcher;
    private final LogoutFilter logoutFilter; //(logoutSuccessUrl,handlers[KeycloakLogoutHandler],logoutRequestMatcher("/sso/logout**","GET"))
    private Resource keycloakConfigFileResource;


    // Our own Atlas filters need to be registered as well
    private final Configuration configuration;
    private final StaleTransactionCleanupFilter staleTransactionCleanupFilter;
    private final ActiveServerFilter activeServerFilter;

    @Inject
    public AtlasSecurityConfig(AtlasKnoxSSOAuthenticationFilter ssoAuthenticationFilter,
                               AtlasCSRFPreventionFilter atlasCSRFPreventionFilter,
                               AtlasAuthenticationFilter atlasAuthenticationFilter,
                               AtlasAuthenticationProvider authenticationProvider,
                               AtlasAuthenticationSuccessHandler successHandler,
                               AtlasAuthenticationFailureHandler failureHandler,
                               AtlasAuthenticationEntryPoint atlasAuthenticationEntryPoint,
                               AdapterDeploymentContextFactoryBean adapterDeploymentContext,
                               KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint,
                               KeycloakAuthenticationProvider keycloakAuthenticationProvider,
                               KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter,
                               KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter,
                               KeycloakLogoutHandler keycloakLogoutHandler,
                               AntPathRequestMatcher logoutRequestMatcher,
                               LogoutFilter logoutFilter,
                               Resource keycloakConfigFileResource,

                               Configuration configuration,
                               StaleTransactionCleanupFilter staleTransactionCleanupFilter,
                               ActiveServerFilter activeServerFilter) {
        this.ssoAuthenticationFilter = ssoAuthenticationFilter;
        this.csrfPreventionFilter = atlasCSRFPreventionFilter;
        this.atlasAuthenticationFilter = atlasAuthenticationFilter;
        this.authenticationProvider = authenticationProvider;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.atlasAuthenticationEntryPoint = atlasAuthenticationEntryPoint;
        this.adapterDeploymentContext = adapterDeploymentContext;
        this.keycloakAuthenticationEntryPoint = keycloakAuthenticationEntryPoint;
        this.keycloakAuthenticationProvider = keycloakAuthenticationProvider;
        this.keycloakPreAuthActionsFilter = keycloakPreAuthActionsFilter;
        this.keycloakAuthenticationProcessingFilter = keycloakAuthenticationProcessingFilter;
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.logoutRequestMatcher = logoutRequestMatcher;
        this.logoutFilter = logoutFilter;
        this.keycloakConfigFileResource = keycloakConfigFileResource;

        this.configuration = configuration;
        this.staleTransactionCleanupFilter = staleTransactionCleanupFilter;
        this.activeServerFilter = activeServerFilter;
    }

    public KeycloakAuthenticationEntryPoint getAuthenticationEntryPoint() throws Exception {
        try {
            KeycloakAuthenticationEntryPoint basicAuthenticationEntryPoint = new KeycloakAuthenticationEntryPoint(adapterDeploymentContext.getObject());
            basicAuthenticationEntryPoint.setRealm("atlas.com");
            return basicAuthenticationEntryPoint;
        }
        catch (Exception e) {
            throw new Exception(e);
        }
    }

    public DelegatingAuthenticationEntryPoint getDelegatingAuthenticationEntryPoint() throws Exception {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPointMap = new LinkedHashMap<>();
        entryPointMap.put(new RequestHeaderRequestMatcher("User-Agent", "Mozilla"), keycloakAuthenticationEntryPoint);
        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(entryPointMap);
        entryPoint.setDefaultEntryPoint(getAuthenticationEntryPoint());
        return entryPoint;

        //todo:  replace existing altas security config with keycloak version that can be found in abstract class
    }

    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    public KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter(){
        return new KeycloakSecurityContextRequestFilter();
    }

    @Inject
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/login.jsp",
                        "/css/**",
                        "/img/**",
                        "/libs/**",
                        "/js/**",
                        "/ieerror.html",
                        "/api/atlas/admin/status",
                        "/api/atlas/admin/metrics");
    }

    protected void configure(HttpSecurity httpSecurity) throws Exception {

        //@formatter:off
        httpSecurity
                .authorizeRequests().anyRequest().authenticated()
//                .antMatchers("/customers*").hasRole("USER")
//                .antMatchers("/admin*").hasRole("ADMIN")
//                .anyRequest().permitAll()
                .and()
                    .headers().disable()
                    .servletApi()
                .and()
                    //.csrf().disable()
                    .csrf()
                    .requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
                .and()
                    .sessionManagement()
                    .enableSessionUrlRewriting(false)
                    .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .sessionFixation()
                    .newSession()
                .and()
                    .addFilterBefore(keycloakPreAuthActionsFilter, LogoutFilter.class)
                    .addFilterBefore(keycloakAuthenticationProcessingFilter, BasicAuthenticationFilter.class)
                    .addFilterAfter(keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter.class)
                    .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(), KeycloakSecurityContextRequestFilter.class)
                    .exceptionHandling()
                .and()
                .httpBasic()
                .authenticationEntryPoint(getDelegatingAuthenticationEntryPoint())
                .and()
                    .formLogin()
                        .loginPage("/login.jsp")
                        .loginProcessingUrl("/j_spring_security_check")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .usernameParameter("j_username")
                        .passwordParameter("j_password")
                .and()
                    .logout()
                        .addLogoutHandler(keycloakLogoutHandler)
                        .deleteCookies("ATLASSESSIONID")
                        .logoutUrl("/logout.html")
                        .permitAll()
                        .logoutSuccessUrl("/login.jsp");

        //@formatter:on

        boolean configMigrationEnabled = !StringUtils.isEmpty(configuration.getString(ATLAS_MIGRATION_MODE_FILENAME));
        if (configuration.getBoolean("atlas.server.ha.enabled", false) ||
                configMigrationEnabled) {
            if(configMigrationEnabled) {
                LOG.info("Atlas is in Migration Mode, enabling ActiveServerFilter");
            } else {
                LOG.info("Atlas is in HA Mode, enabling ActiveServerFilter");
            }
            httpSecurity.addFilterAfter(activeServerFilter, BasicAuthenticationFilter.class);
        }
        httpSecurity
                .addFilterAfter(staleTransactionCleanupFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(ssoAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(atlasAuthenticationFilter, SecurityContextHolderAwareRequestFilter.class)
                .addFilterAfter(csrfPreventionFilter, AtlasAuthenticationFilter.class);
    }
}
