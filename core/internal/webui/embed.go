//go:build webui

package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
)

//go:embed all:dist
var dist embed.FS

// distFS is the dashboard filesystem rooted at the embedded dist directory, so
// index.html lives at "/" as far as http.FileServer is concerned.
var distFS fs.FS = mustSub(dist, "dist")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("webui: embedded dashboard missing: " + err.Error())
	}
	return sub
}

// serve serves the embedded dashboard build with SPA fallback.
func serve(w http.ResponseWriter, r *http.Request) {
	name := path.Clean("/" + r.URL.Path)
	if name == "/" || !exists(distFS, name) {
		// Unknown client route (or root) → serve the app shell.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		http.FileServer(http.FS(distFS)).ServeHTTP(w, r2)
		return
	}
	http.FileServer(http.FS(distFS)).ServeHTTP(w, r)
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}
