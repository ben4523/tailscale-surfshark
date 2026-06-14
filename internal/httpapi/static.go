package httpapi

import (
	"io/fs"
	"net/http"
)

type StaticFS = fs.FS

// MountStatic registers a file server on "/" rooted at the given FS.
// Call this from the composition root after //go:embed populates the FS.
func (s *Server) MountStatic(root StaticFS) {
	s.mux.Handle("/", http.FileServer(http.FS(root)))
}
