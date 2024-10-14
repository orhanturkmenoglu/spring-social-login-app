package com.example.springsecOAUTH2.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class ProjectSecurityConfig {

   /* @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/secure")
                                .authenticated()
                                .anyRequest()
                                .permitAll())
                .formLogin(Customizer.withDefaults())

                // OAUTH2 AKTİF HALE GETİR.oauth 2 ile gelecek olan
                // login page özelleştirme sağlamadık
                //.oauth2Login(Customizer.withDefaults());
                .oauth2Login(oauth2->oauth2
                        .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/profile");
                    }
                }));
        return http.build();
    }*/

  /*  @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/secure")
                                .authenticated()
                                .anyRequest()
                                .permitAll())
                .formLogin(Customizer.withDefaults())

                .oauth2Login(oauth2->oauth2
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/profile");
                            }
                        })
                        // başarız durumlarda yönlendirme.
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error");
                        }));
        return http.build();
    }*/

    /*@Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/secure","/login")
                                .authenticated()
                                .anyRequest()
                                .permitAll())
                .formLogin(Customizer.withDefaults())

                .oauth2Login(oauth2->oauth2
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/profile");
                            }
                        })
                        // özelleştirilmiş login page sayfasına gider
                        .loginPage("/login")
                        // başarız durumlarda yönlendirme.
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error=true");
                        }));
        return http.build();
    }
*/


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/secure","/login")
                                .authenticated()
                                .anyRequest()
                                .permitAll())
                .formLogin(Customizer.withDefaults())

                .oauth2Login(oauth2->oauth2
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/profile");
                            }
                        })
                        // özelleştirilmiş login page sayfasına gider
                        .loginPage("/loginPage")
                        // OIDC kullanıcısı için özelleştirme
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                                .oidcUserService(oidcUserService()))

                        // başarız durumlarda yönlendirme.
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error");
                        }));
        return http.build();
    }

    // OIDC kullanıcı servisini özelleştirin (isteğe bağlı)

    // OIDC kullanıcı servisi
    private OidcUserService oidcUserService() {
        return new OidcUserService();
    }


    // burada yetkilendirme sunucusuna ait bilgileri ClientRegistrationRepository tutacak.
    // bunu da InMemoryClientRegistrationRepository içerisinde yapacak.
    //
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration github = githubClientRegistration();
        System.out.println(github.toString());
        ClientRegistration facebook = facebookClientRegistration();
        System.out.println(facebook.toString());
        ClientRegistration google = googleClientRegistration();
        System.out.println(google.toString());
        return new InMemoryClientRegistrationRepository(github,facebook,google);
    }

    // registrationId : KAYIT İD istediğimiz ismi verebiliriz.. bu yetkilendirme sunuucsu idsi demek
    // clientId: için yetkilendirme sunucusuna uygulamayı kayıt yaptırıp oaradan id almamaız lazım
    // facebook ve github sunucuşarına git.
    private ClientRegistration githubClientRegistration() {
        return CommonOAuth2Provider.GITHUB
                .getBuilder("github")
                .clientId("Ov23liZ0P3KRINbFnBfD") // github üzerinden setting-authapp uygulama kayıt yap oradan gelen id .
                .clientSecret("6da23e424b8cb8919976333d65d43b5838a574b2")  // bunu da aynı yerden client-secret oluştur diyerek aldık.
                .build();
    }

    // meta developer üzerinden myApp uygulamamızı oluşturup kaydetcez.
    // kapsamı public_profile ve email de aktif hale getircez.
    // id ve clientsecret oluşturduğumuz yerden aldım
    private ClientRegistration facebookClientRegistration() {
        return CommonOAuth2Provider.FACEBOOK
                .getBuilder("facebook")
                .clientId("521677720769240")
                .clientSecret("98c4e057aaf13d31a934f772c640a0a6")
                .build();
    }

    private ClientRegistration googleClientRegistration() {
        return CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId("1054762375979-6dcah0k9b8p2dek25i0fe8do05mst093.apps.googleusercontent.com")
                .clientSecret("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")
                .build();
    }

}
