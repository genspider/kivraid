# Forward auth

Kivraid can protect applications that have no native SSO support through
the reverse proxy's auth subrequest mechanism (Traefik `forwardAuth`,
nginx `auth_request`, Caddy `forward_auth`).

The proxy asks `GET /outpost/auth` on every request:

- **Authenticated**: `200` with identity headers the proxy can copy
  upstream: `Remote-User`, `Remote-Email`, `Remote-Name`, `Remote-Groups`
  (comma-separated; a group whose name contains a comma is left out rather
  than split).
- **Anonymous**: a redirect to sign in — if the target host is allowlisted —
  otherwise `401`.

### How a protected host gets signed in

Kivraid's session cookie belongs to Kivraid's host: the browser never sends
it to `app.example.com`. So each protected host gets a session of its own,
through a one-time code (the same design as Authentik's proxy outpost):

1. An anonymous request to `app.example.com` is redirected to Kivraid's
   `/outpost/start`, and a `kivraid_fa_state` cookie is set on
   `app.example.com`.
2. Kivraid signs the user in if needed (password, two-factor, a forced
   password change, the application's own policy), then issues a code valid
   for two minutes, for that host and that state only, and redirects to
   `https://app.example.com/.kivraid/callback`.
3. The proxy sends the callback to Kivraid like any other request to the
   host. Kivraid redeems the code once and sets a `kivraid_fa` session
   cookie on `app.example.com`, then returns to the page first asked for.

That session lasts no longer than the Kivraid session it came from, and
ends with it: signing out of Kivraid, revoking the session, changing the
password or deactivating the account. Group and two-factor policies are
checked again on every request. When Kivraid itself serves the protected
host (or a parent of it that shares its cookie), its own session cookie is
used directly.

Because the redirects leave Kivraid's own origin, the allowed hosts must be
declared explicitly (open-redirect protection):

```yaml
# kivraid.yaml
forward_auth:
  domains:
    - ".home.example.com"      # any subdomain of home.example.com
    - "grafana.example.com"    # exact host
```

Forward auth means every request reaches Kivraid through the reverse
proxy, so also set `trusted_proxies` to the proxy's address — otherwise
rate limiting and the audit log attribute everything to the proxy's IP.
See [configuration.md](configuration.md#tls-and-the-issuer).

## Traefik

```yaml
http:
  middlewares:
    kivraid:
      forwardAuth:
        address: "https://auth.example.com/outpost/auth"
        authResponseHeaders:
          - Remote-User
          - Remote-Email
          - Remote-Name
          - Remote-Groups
  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      middlewares: [kivraid]
      service: myapp
```

The middleware also covers the `/.kivraid/callback` path of the host, so the
code exchange needs no extra route: Traefik relays Kivraid's redirect and
cookies to the browser.

Leave `trustForwardHeader` off (the default): Traefik then sets
`X-Forwarded-Host` from the request it routed. Turned on, it passes along
whatever `X-Forwarded-Host` the client (or a load balancer in front) sent,
and Kivraid would apply the policy of the application named there instead
of the one requested.

## nginx

`auth_request` only understands `2xx`, `401` and `403`, so nginx uses the
`/outpost/auth/nginx` variant, which answers `401` where the others
redirect; `error_page` then sends the browser through `/outpost/auth` for
the redirect itself. The callback path is proxied to Kivraid directly.

```nginx
location / {
    auth_request /kivraid-auth;
    auth_request_set $user   $upstream_http_remote_user;
    auth_request_set $email  $upstream_http_remote_email;
    auth_request_set $groups $upstream_http_remote_groups;
    proxy_set_header Remote-User   $user;
    proxy_set_header Remote-Email  $email;
    proxy_set_header Remote-Groups $groups;
    error_page 401 = @kivraid-signin;
    proxy_pass http://myapp;
}

location = /kivraid-auth {
    internal;
    proxy_pass https://auth.example.com/outpost/auth/nginx;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Uri   $request_uri;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}

location @kivraid-signin {
    rewrite ^ /outpost/auth break;
    proxy_pass https://auth.example.com;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Uri   $request_uri;
}

location = /.kivraid/callback {
    proxy_pass https://auth.example.com/outpost/callback;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
}
```

## Caddy

Caddy returns Kivraid's redirects and cookies to the browser for any
non-`2xx` answer, the callback path included.

```caddyfile
app.example.com {
    forward_auth https://auth.example.com {
        uri /outpost/auth
        copy_headers Remote-User Remote-Email Remote-Name Remote-Groups
    }
    reverse_proxy myapp:8080
}
```

## Per-application authorization

Register a **forward-auth application** in Admin → Applications (choose
the "Forward auth" integration) and list its protected hosts. When a
request's `X-Forwarded-Host` matches one of them, Kivraid enforces that
application's group access policy: members who fail it get `403`, so the
protected app never sees an unauthorized user. An application open to
*Everyone signed in* allows any authenticated user; one restricted to
groups stays locked if those groups are deleted. Give it a launch URL to make it
appear in the user portal's launcher.

The `forward_auth.domains` config still governs which hosts may be used
as post-login redirect targets (open-redirect protection); a registered
proxy application's hosts are trusted for that too.

## Notes

- The identity headers are only trustworthy when set by the proxy —
  make sure the upstream application cannot receive them directly from
  clients.
