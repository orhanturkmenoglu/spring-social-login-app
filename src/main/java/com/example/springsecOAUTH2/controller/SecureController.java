package com.example.springsecOAUTH2.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

// basit bir mvc yoludur.geriye html türünde sayfa dönderecem
@Controller
public class SecureController {

    @GetMapping("/secure")
    public String securePage(Authentication authentication){
        if (authentication instanceof UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken){
            System.out.println(usernamePasswordAuthenticationToken);
        }else if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken){
            System.out.println(oAuth2AuthenticationToken);
        }
        return "secure";
    }

    // Giriş sayfasını gösteren metot
    @GetMapping("/loginPage")
    public String login() {
        return "loginPage"; // login.html dosyasını döndür
    }
}
