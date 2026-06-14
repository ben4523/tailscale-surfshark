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
	logger          Logger
}

func New(w WhoisFunc, allowed []string) *Middleware {
	set := map[string]struct{}{}
	for _, u := range allowed {
		set[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
	}
	return &Middleware{whois: w, allowedLowerSet: set, allowedRaw: allowed}
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
		user, err := m.whois.Whois(r.Context(), ip)
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("auth: whois failed", "ip", ip, "error", err.Error())
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, ok := m.allowedLowerSet[strings.ToLower(strings.TrimSpace(user))]; !ok {
			if m.logger != nil {
				m.logger.Warn("auth: denied",
					"ip", ip,
					"resolved_user", user,
					"allowed_users", m.allowedRaw,
					"hint", "add this user to TS_ALLOWED_USERS in .env exactly as shown above",
				)
			}
			// Echo the resolved identity in the body so the operator can see it
			// from a browser without needing docker logs access.
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, fmt.Sprintf(
				"forbidden — tailscale identity %q is not in TS_ALLOWED_USERS.\n"+
					"Edit .env, set TS_ALLOWED_USERS to include exactly that string, then `docker compose up -d`.\n",
				user,
			))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, user))
		next.ServeHTTP(w, r)
	})
}

func UserFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}
