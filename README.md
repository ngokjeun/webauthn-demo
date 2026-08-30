# WebAuthn Demo

A small Java relying-party server demonstrating WebAuthn (passkey) **registration**,
**login**, and an account **settings** page for managing passkeys.

- Backend: Spring Boot 3 + [Yubico `webauthn-server-core`](https://github.com/Yubico/java-webauthn-server)
- Storage: in-memory only (restarting the app clears all users/passkeys) — this is a demo, not production auth
- Frontend: plain HTML/CSS/JS served from `src/main/resources/static`, using `navigator.credentials.create()` / `.get()`

## Requirements

- JDK 17+
- Maven (or use the included wrapper, `mvnw` / `mvnw.cmd`, which downloads Maven automatically)

## Run it

```bash
./mvnw spring-boot:run      # macOS/Linux
mvnw.cmd spring-boot:run    # Windows
```

Then open **http://localhost:8080**. Passkeys require a "secure context" — `http://localhost`
is treated as secure by browsers, so this works without HTTPS for local testing.

## Pages

- `/register.html` — create an account (creates a passkey for a new username)
- `/login.html` — sign in with an existing passkey (leave username blank to use a
  discoverable/resident passkey, if your device supports the passkey autofill flow)
- `/settings.html` — rename/remove passkeys, add another passkey, edit display name

## Config

Edit `src/main/resources/application.properties`:

```properties
webauthn.rp-id=localhost
webauthn.rp-name=WebAuthn Demo
webauthn.origin=http://localhost:8080
```

If you deploy this somewhere else, `webauthn.rp-id` must be the domain (no scheme/port)
and `webauthn.origin` must be the exact origin the browser sees (including scheme/port).

## Notes

- This was written without access to a local JDK/Maven to compile-verify it, so the
  library API calls are based on a careful reading of the `webauthn-server-core:2.6.0`
  source; if `mvnw spring-boot:run` fails to compile, check the error against the
  Yubico library docs at https://developers.yubico.com/java-webauthn-server/.
