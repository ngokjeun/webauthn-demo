package com.example.webauthndemo.model;

import com.yubico.webauthn.data.ByteArray;

import java.time.Instant;

public class StoredCredential {
    private final ByteArray credentialId;
    private final ByteArray userHandle;
    private final ByteArray publicKeyCose;
    private long signatureCount;
    private String nickname;
    private final Instant createdAt;

    public StoredCredential(
            ByteArray credentialId,
            ByteArray userHandle,
            ByteArray publicKeyCose,
            long signatureCount,
            String nickname) {
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.publicKeyCose = publicKeyCose;
        this.signatureCount = signatureCount;
        this.nickname = nickname;
        this.createdAt = Instant.now();
    }

    public ByteArray getCredentialId() {
        return credentialId;
    }

    public ByteArray getUserHandle() {
        return userHandle;
    }

    public ByteArray getPublicKeyCose() {
        return publicKeyCose;
    }

    public long getSignatureCount() {
        return signatureCount;
    }

    public void setSignatureCount(long signatureCount) {
        this.signatureCount = signatureCount;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
