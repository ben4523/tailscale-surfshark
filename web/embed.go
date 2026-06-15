// Package web embeds the static UI assets so they can be served from the binary.
package web

import (
	"embed"
	"mime"
)

//go:embed index.html app.js style.css manifest.webmanifest icon.svg
var FS embed.FS

func init() {
	// Go's net/http uses mime.TypeByExtension to derive Content-Type for
	// static files. .webmanifest isn't in the default table; without this
	// registration Safari and Chrome refuse the PWA manifest.
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
}
