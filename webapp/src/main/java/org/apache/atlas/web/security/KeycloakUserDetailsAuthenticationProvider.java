package org.apache.atlas.web.security;

/*
 * Copyright 2015 Smartling, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.atlas.web.dao.UserDao;
import org.apache.atlas.web.security.token.KeycloakUserDetailsAuthenticationToken;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.inject.Inject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * Provides a {@link KeycloakAuthenticationProvider Keycloak authentication provider} capable of
 * swapping the Keycloak principal with a {@link UserDetails user details} principal.
 * <p>
 * The supplied {@link UserDetailsService user details service} is consulted using the Keycloak
 * access token's email as the username.
 * </p>
 * <p>
 * The original Keycloak principal is available from the {@link KeycloakAuthenticationToken}:
 * <pre>
 *          KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication());
 *          KeycloakAccount account = token.getAccount();
 *          Principal = account.getPrincipal();
 *     </pre>
 *
 * @author <a href="mailto:srossillo@smartling.com">Scott Rossillo</a>
 * @see UserDetailsService#loadUserByUsername
 * @see KeycloakUserDetailsAuthenticationToken
 */

@Component
public class KeycloakUserDetailsAuthenticationProvider extends AtlasAbstractAuthenticationProvider {
    private static Logger LOG = LoggerFactory.getLogger(AtlasPamAuthenticationProvider.class);
    private boolean isDebugEnabled = LOG.isDebugEnabled();
    private UserDetailsService userDetailsService;


    @Inject
    public KeycloakUserDetailsAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication auth = getKeycloakAuthentication(authentication);
        if (auth != null && auth.isAuthenticated()) {
            return auth;
        } else {
            throw new AtlasAuthenticationException("Keycloak Authentication Failed");
        }
    }

    private Authentication getKeycloakAuthentication(Authentication authentication) {
        if (isDebugEnabled) {
            LOG.debug("==> AtlasKeycloakUserDetailsAuthenticationProvider getKeycloakAuthentication");
        }
        try {
            Resource inputStream = (Resource) new InputStreamResource(new FileInputStream("/home/rikus/Documents/ZenAptix/atlas/webapp/src/main/resources/keycloak.json"));
            AdapterDeploymentContextFactoryBean context = new AdapterDeploymentContextFactoryBean(inputStream);
            Set<String> roles = new HashSet<String>();
            roles.add("");
            Principal test_principal = (Principal) authentication.getPrincipal();
            User user_principal = new User(authentication.getPrincipal().toString(),authentication.getCredentials().toString(),authentication.getAuthorities());
            AccessToken accessToken = new AccessToken();
            accessToken.setOtherClaims("ORG_PROPERTY_NAME", "zenAptix");
            accessToken.setOtherClaims("PERMISSIONS_PROPERTY_NAME", "");

            RefreshableKeycloakSecurityContext ksc = new RefreshableKeycloakSecurityContext(null, null, "accessTokenString", accessToken, "idTokenString", null, "refreshTokenString");
            SimpleKeycloakAccount account = new SimpleKeycloakAccount(test_principal,roles,ksc);
            KeycloakAuthenticationToken testToken = new KeycloakAuthenticationToken(account,true);

//            KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication.getPrincipal();
//            KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) super.authenticate(authentication);
            KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) super.authenticate(testToken);
            String username;
            UserDetails userDetails;

            LOG.info("============Authenticating using KeycloakUserDetailsAuth===============");

            if (token == null) {
                return null;
            }

            username = this.resolveUsername(token);
            userDetails = userDetailsService.loadUserByUsername(username);

            authentication = new KeycloakUserDetailsAuthenticationToken(userDetails, token.getAccount(), token.getAuthorities());
            return authentication;


        } catch (Exception e) {
            LOG.debug("Keycloak Authentication Failed", e);
        }
        if (isDebugEnabled) {
            LOG.debug("<== AtlasKeycloakUserDetailsAuthenticationProvider getKeycloakAuthentication");
        }
        return authentication;
    }

    /**
     * Returns the username from the given {@link KeycloakAuthenticationToken}. By default, this method
     * resolves the username from the token's {@link KeycloakPrincipal}'s name. This value can be controlled
     * via <code>keycloak.json</code>'s
     * <a href="http://docs.jboss.org/keycloak/docs/1.2.0.CR1/userguide/html/ch08.html#adapter-config"><code>principal-attribute</code></a>.
     * For more fine-grained username resolution, override this method.
     *
     * @param token the {@link KeycloakAuthenticationToken} from which to extract the username
     * @return the username to use when loading a user from the this provider's {@link UserDetailsService}.
     * @see UserDetailsService#loadUserByUsername
     * @see OidcKeycloakAccount#getPrincipal
     */
    protected String resolveUsername(KeycloakAuthenticationToken token) {

        Assert.notNull(token, "KeycloakAuthenticationToken required");
        Assert.notNull(token.getAccount(), "KeycloakAuthenticationToken.getAccount() cannot be return null");
        OidcKeycloakAccount account = token.getAccount();
        Principal principal = account.getPrincipal();

        return principal.getName();
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
