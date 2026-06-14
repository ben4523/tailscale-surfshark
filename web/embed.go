// Package web embeds the static UI assets so they can be served from the binary.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
