package auth

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type WhoisFunc interface {
	Whois(ctx context.Context, ip string) (string, error)
}

type ctxKey struct{}

type Middleware struct {
	whois           WhoisFunc
	allowedLowerSet map[string]struct{}
}

func New(w WhoisFunc, allowed []string) *Middleware {
	set := map[string]struct{}{}
	for _, u := range allowed {
		set[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
	}
	return &Middleware{whois: w, allowedLowerSet: set}
}

func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		user, err := m.whois.Whois(r.Context(), ip)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, ok := m.allowedLowerSet[strings.ToLower(user)]; !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
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
