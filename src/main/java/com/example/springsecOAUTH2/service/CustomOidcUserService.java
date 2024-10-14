package com.example.springsecOAUTH2.service;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

@Component
public class CustomOidcUserService  extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // Burada kullanıcı bilgilerini özelleştirebilirsiniz
        // Örneğin: Kullanıcı bilgilerini bir veritabanına kaydedebilirsiniz


        // Örnek: Kullanıcı bilgilerini özelleştirme
        OidcUser oidcUser = super.loadUser(userRequest);
        OidcUserInfo userInfo = oidcUser.getUserInfo();
        System.out.println("UserInfo"+userInfo);
        return oidcUser;
    }
}
