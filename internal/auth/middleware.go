package auth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

type WhoisFunc interface {
	Whois(ctx context.Context, ip string) (string, error)
}

// Logger is the minimal interface this middleware needs for diagnostics.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
}

type ctxKey struct{}

type Middleware struct {
	whois           WhoisFunc
	allowedLowerSet map[string]struct{}
	allowedRaw      []string
	allowAny        bool // true when "*" is in the allowed list
	logger          Logger
}

// New constructs the middleware.
//
// `allowed` is a list of tailnet identities. Special value "*" allows any
// caller whose tailnet identity resolves (i.e., any tailnet member). Useful
// for personal tailnets and for tagged devices that surface as
// "tagged-devices" rather than a real email.
func New(w WhoisFunc, allowed []string) *Middleware {
	set := map[string]struct{}{}
	allowAny := false
	for _, u := range allowed {
		t := strings.ToLower(strings.TrimSpace(u))
		if t == "*" {
			allowAny = true
			continue
		}
		set[t] = struct{}{}
	}
	return &Middleware{whois: w, allowedLowerSet: set, allowedRaw: allowed, allowAny: allowAny}
}

// SetLogger attaches a logger so denied requests can be diagnosed in the host
// logs. Without this, 403 silently rejects.
func (m *Middleware) SetLogger(l Logger) { m.logger = l }

func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		// Preferred: identity injected by `tailscale serve` over HTTPS.
		user := strings.TrimSpace(r.Header.Get("Tailscale-User-Login"))

		if user == "" {
			// No header. Two possible paths:
			//
			//   a) `tailscale serve --http=...` over plain HTTP. The serve proxy
			//      strips the original client and presents the request from
			//      loopback. Identity headers are only injected on HTTPS, so we
			//      can't know who the caller is — but we DO know that
			//      `tailscale serve` only accepts authenticated tailnet members,
			//      so loopback is a proxy-vouched tailnet caller.
			//
			//   b) Direct connection from a Tailscale-routed IP (kernel mode).
			//      Resolve identity via whois.
			if isLoopback(ip) {
				// Treat as a generic tailnet member. Real identity unknown.
				// Allowed only when the operator opted into the wildcard (*).
				user = "tailnet-member-via-serve"
			} else {
				var werr error
				user, werr = m.whois.Whois(r.Context(), ip)
				if werr != nil {
					if m.logger != nil {
						m.logger.Warn("auth: whois failed and no Tailscale-User-Login header",
							"ip", ip, "error", werr.Error())
					}
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}
		if !m.allowAny {
			if _, ok := m.allowedLowerSet[strings.ToLower(strings.TrimSpace(user))]; !ok {
				if m.logger != nil {
					m.logger.Warn("auth: denied",
						"ip", ip,
						"resolved_user", user,
						"allowed_users", m.allowedRaw,
						"hint", "add this user to TS_ALLOWED_USERS in .env exactly as shown above (or set TS_ALLOWED_USERS=* to allow any tailnet member)",
					)
				}
				// Echo the resolved identity in the body so the operator can see it
				// from a browser without needing docker logs access.
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, fmt.Sprintf(
					"forbidden -- tailscale identity %q is not in TS_ALLOWED_USERS.\n\n"+
						"Either:\n"+
						"  - edit .env and add this exact string to TS_ALLOWED_USERS, OR\n"+
						"  - set TS_ALLOWED_USERS=* to allow any member of your tailnet.\n\n"+
						"Then: docker compose up -d\n",
					user,
				))
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, user))
		next.ServeHTTP(w, r)
	})
}

func UserFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

// isLoopback reports whether s is "127.0.0.1", "::1", or any other
// loopback IP literal. Used to recognize callers proxied in by
// `tailscale serve` whose original source IP is hidden.
func isLoopback(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
