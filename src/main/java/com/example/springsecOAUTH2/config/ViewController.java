package com.example.springsecOAUTH2.config;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/profile")
    public String profile(OAuth2AuthenticationToken token, Model model){
        model.addAttribute("name", token.getPrincipal().getAttribute("name"));
        model.addAttribute("email", token.getPrincipal().getAttribute("email"));
        model.addAttribute("photo", token.getPrincipal().getAttribute("picture"));
        return "user-profile";
    }

    @GetMapping("/user")
    public String userInfo (@AuthenticationPrincipal OAuth2User principal,Model model){
        if (principal != null) {
            model.addAttribute("name", principal.getAttribute("name"));
            model.addAttribute("email", principal.getAttribute("email"));
        }
        return "user-profile"; // user.html dosyasını döndür
    }
}
