package com.example.webauthndemo;

import com.example.webauthndemo.storage.InMemoryUserStorage;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class WebAuthnConfig {

    @Bean
    public RelyingPartyIdentity relyingPartyIdentity(
            @Value("${webauthn.rp-id:localhost}") String rpId,
            @Value("${webauthn.rp-name:WebAuthn Demo}") String rpName) {
        return RelyingPartyIdentity.builder().id(rpId).name(rpName).build();
    }

    @Bean
    public RelyingParty relyingParty(
            RelyingPartyIdentity rpIdentity,
            InMemoryUserStorage userStorage,
            @Value("${webauthn.origin:http://localhost:8080}") String origin) {
        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(userStorage)
                .origins(Set.of(origin))
                .allowOriginPort(false)
                .allowOriginSubdomain(false)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(true)
                .build();
    }
}
