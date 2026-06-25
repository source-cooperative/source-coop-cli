# Ory Network: `urls.device.verification` / `urls.device.success` silently dropped — device flow unusable

**Environment:** Ory Network (managed). OAuth2 device authorization grant (RFC 8628).

## What works

1. **The grant + code issuance.** Adding the device grant to an OAuth2 client
   succeeds, and the device-authorization endpoint issues codes:

   ```bash
   ory update oauth2-client <CLIENT_ID> \
     --grant-type authorization_code --grant-type refresh_token \
     --grant-type urn:ietf:params:oauth:grant-type:device_code \
     --token-endpoint-auth-method none …

   curl -X POST https://<PROJECT_SLUG>.projects.oryapis.com/oauth2/device/auth \
     -d client_id=<CLIENT_ID> -d 'scope=openid offline_access'
   # → returns user_code, device_code, verification_uri, verification_uri_complete ✓
   ```

2. **The verification mechanism itself.** A self-hosted verification page would
   work fully. Taking the `device_challenge` that Hydra puts in the fallback URL
   and accepting the code via the admin API returns `200` with a `redirect_to`
   that continues into the normal login/consent flow:

   ```bash
   curl -X PUT "https://<PROJECT_SLUG>.projects.oryapis.com/admin/oauth2/auth/requests/device/accept?device_challenge=<CHALLENGE>" \
     -H "Authorization: Bearer <PROJECT_API_KEY>" -H "Content-Type: application/json" \
     -d '{"user_code":"<USER_CODE>"}'
   # → 200 { "redirect_to": ".../oauth2/device/verify?client_id=…&device_verifier=…&user_code=…" }
   ```

   So every step is functional — issuance, code entry, accept, and hand-off to
   login/consent. **The only missing link is getting Hydra to send the browser
   to a custom verification page in the first place.**

## What fails

Setting the device verification/success UI URLs is **silently discarded**:

```bash
ory patch project <PROJECT_SLUG> \
  --add '/services/oauth2/config/urls/device={"verification":"https://app.example.com/device","success":"https://app.example.com/device/success"}'
# → "Project updated successfully!"  (no error, device NOT in the ignored-keys warning)
```

Two ways to confirm it didn't persist:

```bash
# 1. Read-back: device key is absent
ory get project <PROJECT_SLUG> --format json | jq '.services.oauth2.config.urls'
# → { consent, error, login, logout, post_logout_redirect, registration, self }   ← no "device"

# 2. Live flow still hits the built-in fallback
#   following verification_uri_complete 302-redirects to:
#   https://<PROJECT_SLUG>.projects.oryapis.com/oauth2/fallbacks/device?device_challenge=…
```

## Root cause

Ory Network persists Hydra config as a flat `normalizedProjectRevision`, which
has **no field** for `urls.device.verification` / `urls.device.success` (only
login/consent/logout/error/registration/post_logout_redirect/self exist).
Self-hosted Hydra's config schema defines these keys; the managed Network schema
does not expose them, so the API accepts the patch and drops the key. Confirmed
across `ory patch project`, `ory patch oauth2-config`, and `ory update` — all
normalize into the same schema.

## Impact

With `urls.device.verification` unset, Hydra routes the user to
`/oauth2/fallbacks/device`, a **hardcoded static error page** ("configuration
key `urls.device.verification` is not set") — no code-entry form. Since the
verification mechanism itself works (see above), this is purely a routing gap:
there is no way to point the browser at a working verification UI. The user can
never approve the device, so the client's token poll never completes and device
login hangs until the code expires.

## Ask

Expose `urls.device.verification` / `urls.device.success` in the Ory Network
project config schema (the Hydra device grant shipped in v25.4.0, but these URL
keys aren't settable on Network), or document the supported way to point the
device flow at a custom verification UI.

## References

- [Ory — Device Authorization docs](https://www.ory.com/docs/oauth2-oidc/device-authorization)
- [NormalizedProjectRevision schema (ory/client-go)](https://github.com/ory/client-go/blob/master/docs/NormalizedProjectRevision.md)
- [Ory v25.4.0 changelog](https://changelog.ory.com/announcements/ory-v25-4-0-released)
- [ory/hydra #2416](https://github.com/ory/hydra/issues/2416) / [PR #3912](https://github.com/ory/hydra/pull/3912)
- [Ory community thread — device URL config not persisting](https://archive.ory.sh/t/30289954/)
