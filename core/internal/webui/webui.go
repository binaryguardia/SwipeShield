// Package webui serves the SwipeShield management dashboard. The dashboard is
// a Vite/React single-page app (dashboard/). Two build modes exist:
//
//   - default build (no tags): serves a stub page telling the operator the UI
//     was not bundled. Keeps the plain `go build ./...` dependency-free.
//   - `-tags webui`: embeds the built dashboard from dashboard/dist via
//     embed.go. Packaging scripts build with this tag after `npm run build`.
//
// In both modes Handler() returns an http.Handler with SPA fallback so client
// routes (e.g. /sites/:id) resolve to index.html.
package webui

import (
	"net/http"
)

// Handler returns the dashboard HTTP handler.
func Handler() (http.Handler, error) {
	return spaHandler(), nil
}

// spaHandler serves a static tree with fallback to index.html.
func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r)
	})
}
