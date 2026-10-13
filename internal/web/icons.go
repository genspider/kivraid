package web

import (
	"fmt"
	"html/template"
)

// The icon set is codehearth's (Apache-2.0, same authors), so the two
// products share one visual vocabulary: 16px linear icons drawn on a 24x24
// grid with a 1.75 stroke, in the Atlaskit style. Each entry is the d
// attribute of a single path.
var iconPaths = map[string]string{
	"search":           "M10.5 3.5a7 7 0 1 1 0 14 7 7 0 0 1 0-14zM20.5 20.5l-5-5",
	"sun":              "M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8zM12 2.5v2m0 15v2M4.6 4.6L6 6m12 12l1.4 1.4M2.5 12h2m15 0h2M4.6 19.4L6 18M18 6l1.4-1.4",
	"moon":             "M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z",
	"monitor":          "M4 4.5h16a1 1 0 0 1 1 1V16a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5.5a1 1 0 0 1 1-1zM9 21h6m-3-4v4",
	"plus":             "M12 5v14M5 12h14",
	"cross":            "M6 6l12 12M18 6L6 18",
	"check":            "M5 12.5l4.5 4.5L19 7",
	"chevron-down":     "M6 9l6 6 6-6",
	"chevron-up":       "M6 15l6-6 6 6",
	"chevron-right":    "M9 6l6 6-6 6",
	"chevron-left":     "M15 6l-6 6 6 6",
	"arrow-left":       "M19 12H5m6-6l-6 6 6 6",
	"arrow-right":      "M5 12h14m-6-6l6 6-6 6",
	"warning":          "M12 3.5l9 16H3l9-16zM12 10v4m0 3v.5",
	"info":             "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm0 8v5m0-8.5v.5",
	"error":            "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm0 5v5m0 3v.5",
	"question":         "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm-2.5 6.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7m0 3v.5",
	"settings":         "M18.26 10.67L21.26 10.37L21.26 13.63L18.26 13.33L16.28 16.76L18.04 19.2L15.21 20.83L13.98 18.09L10.02 18.09L8.79 20.83L5.96 19.2L7.72 16.76L5.74 13.33L2.74 13.63L2.74 10.37L5.74 10.67L7.72 7.24L5.96 4.8L8.79 3.17L10.02 5.91L13.98 5.91L15.21 3.17L18.04 4.8L16.28 7.24ZM8.6 12a3.4 3.4 0 1 0 6.8 0a3.4 3.4 0 1 0 -6.8 0",
	"lock":             "M7 10.5V8a5 5 0 0 1 10 0v2.5M6 10.5h12a1 1 0 0 1 1 1V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8.5a1 1 0 0 1 1-1zm6 4.5v2",
	"unlock":           "M7 10.5V8a5 5 0 0 1 9.6-2M6 10.5h12a1 1 0 0 1 1 1V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8.5a1 1 0 0 1 1-1zm6 4.5v2",
	"user":             "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-7 8.5a7 7 0 0 1 14 0",
	"users":            "M9 12a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zm-6 8a6 6 0 0 1 12 0M15.5 5.5a3.5 3.5 0 0 1 0 6.5M17 14a6 6 0 0 1 4 5.5",
	"folder":           "M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2h8.5A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5v-11z",
	"repo":             "M6 3.5h12a1 1 0 0 1 1 1v15a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-15a1 1 0 0 1 1-1zM5 16.5h14M9 3.5v13",
	"branch":           "M7 4.5v10M7 14.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm0-10a2.5 2.5 0 1 0 0-5M17 9.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zm0 0c0 4-10 3-10 7",
	"commit":           "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zM3 12h5.5m7 0H21",
	"pull-request":     "M7 7.5v12m0-12a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zm0 12a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm10 0a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm0 0V9.5a2 2 0 0 0-2-2h-3m2.5-2.5L12 7.5l2.5 2.5",
	"code":             "M8 7l-5 5 5 5m8-10l5 5-5 5M14 4l-4 16",
	"clock":            "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm0 4v5l3.5 2",
	"file":             "M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zm7 0v5h5",
	"home":             "M4 11l8-7 8 7v9a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1v-9z",
	"menu":             "M4 7h16M4 12h16M4 17h16",
	"more":             "M6 12h.01M12 12h.01M18 12h.01",
	"more-vertical":    "M12 6h.01M12 12h.01M12 18h.01",
	"sign-out":         "M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 8l-4 4 4 4m-4-4h11",
	"edit":             "M4 20h4l11-11-4-4L4 16v4zM13 7l4 4",
	"trash":            "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6m4-6v6",
	"copy":             "M8 8h11a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1zm-3 8H4V4a1 1 0 0 1 1-1h11v1",
	"link":             "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5",
	"external":         "M14 4h6v6m0-6l-9 9M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5",
	"shield":           "M12 3l8 3v6c0 5-3.5 8-8 9.5C7.5 20 4 17 4 12V6l8-3zm-3 9l2 2 4-4",
	"key":              "M14 10a4 4 0 1 0-3.4 3.9L4 20.5V22h4v-2h2v-2h2l1.5-1.5A4 4 0 0 0 14 10zm1-2h.01",
	"refresh":          "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
	"play":             "M8 5.5v13l10.5-6.5L8 5.5z",
	"filter":           "M4 5h16l-6 8v6l-4-2v-4L4 5z",
	"eye":              "M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12zm9.5 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
	"star":             "M12 3.5l2.7 5.6 6.1.8-4.5 4.3 1.1 6.1L12 17.4l-5.4 2.9 1.1-6.1L3.2 9.9l6.1-.8L12 3.5z",
	"fork":             "M7 4.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm10 0a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm-5 10a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM7 9.5c0 3 5 2 5 5m5-5c0 3-5 2-5 5",
	"archive":          "M3 5h18v4H3V5zm1 4h16v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9zm6 4h4",
	"globe":            "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm-9 9h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
	"sidebar-collapse": "M4 5h16v14H4V5zm5 0v14M14 10l-2 2 2 2",
	"sidebar-expand":   "M4 5h16v14H4V5zm5 0v14M13 10l2 2-2 2",
	"dashboard":        "M4 4h7v7H4V4zm9 0h7v5h-7V4zM4 13h7v7H4v-7zm9-2h7v9h-7v-9z",
	"bell":             "M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15L6 16zm4 4a2 2 0 0 0 4 0",
	"arrow-up-right":   "M7 17L17 7M9 7h8v8",
	"download":         "M12 4v11m-5-5l5 5 5-5M4 19h16",
	"upload":           "M12 15V4m-5 5l5-5 5 5M4 19h16",
	"image":            "M4 5h16v14H4V5zm3 10l3.5-4 3 3.5 2-2L19 15M8.5 9.5h.01",
	"mail":             "M3 6h18v12H3V6zm0 1l9 6 9-6",
	"server":           "M4 4h16v6H4V4zm0 10h16v6H4v-6zm3-7h.01M7 17h.01",
	"activity":         "M3 12h4l3-7 4 14 3-7h4",
	"history":          "M3.5 12a8.5 8.5 0 1 0 2.5-6M3.5 4v4h4M12 7.5V12l3 2",
	"comment":          "M4 5h16v11H9l-5 4V5z",
	"merge":            "M7 4.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm0 10a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm10-3a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM7 9.5v5m0-5c0 3 6 3 7.5 4",
	"check-circle":     "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm-4 9l3 3 5-6",
	"needs-work":       "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm-4.5 9h9",
	"cross-circle":     "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zM9 9l6 6m0-6l-6 6",
	"task":             "M4 5h16v14H4V5zm4 7l2.5 2.5L15 10",
	"send":             "M4 12l16-8-5 16-3-6-8-2z",
	"auto-merge":       "M7 4.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm0 10a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm10-3a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM7 9.5v5m0-5c0 3 6 3 7.5 4M17 12.7v1.3l1 .6",
	"check-square":     "M5 4h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm3 8l3 3 5-6",
	"smile":            "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zM8.5 14a4.5 4.5 0 0 0 7 0M9 9.5h.01M15 9.5h.01",
	"add":              "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18zm0 5v8m-4-4h8",
	"chevrons-up":      "M6 17l6-6 6 6M6 11l6-6 6 6",
	"chevrons-down":    "M6 7l6 6 6-6M6 13l6 6 6-6",
	"bar":              "M5 12h14",
	"bolt":             "M13 3L5 13.5h6L11 21l8-10.5h-6L13 3z",
	"bookmark":         "M7 4h10a1 1 0 0 1 1 1v15l-6-4-6 4V5a1 1 0 0 1 1-1z",
	"bug":              "M9 7a3 3 0 0 1 6 0M6.5 10h11v4a5.5 5.5 0 0 1-11 0v-4zM3 11h3.5M17.5 11H21M4 17l2.8-1.7M17.2 15.3L20 17M5 6l2.5 2M19 6l-2.5 2",
	"tag":              "M3.5 4.5v6.3l9.2 9.2a1 1 0 0 0 1.4 0l5.9-5.9a1 1 0 0 0 0-1.4L10.8 3.5H4.5a1 1 0 0 0-1 1zM8 8h.01",
	"compare":          "M4 8h14m-4-4l4 4-4 4M20 16H6m4-4l-4 4 4 4",
	"pipeline":         "M2.5 9.5h5v5h-5v-5zm14-5.5h5v5h-5V4zm0 11h5v5h-5v-5zM7.5 12H12m0-5.5v11m0-11h4.5M12 17.5h4.5",
	"rocket":           "M12 3c3 2.2 4.5 5.6 4 10l-2 3h-4l-2-3c-.5-4.4 1-7.8 4-10zM8 13l-3 2.5V19l5-3M16 13l3 2.5V19l-5-3M12 8.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zM10.5 18.5l1.5 3 1.5-3",
	"cloud":            "M7 18.5a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 17.9 9a4.75 4.75 0 0 1-.4 9.5H7z",
	"package":          "M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zm-8 4.5l8 4.5 8-4.5M12 12v9M8 5.25l8 4.5",
	"component":        "M4.5 4.5h6v6h-6zM13.5 4.5h6v6h-6zM4.5 13.5h6v6h-6zM16.5 13.5v6M13.5 16.5h6",
}

// icon renders a named icon as inline SVG, sized 16px by default; extra
// classes (sizes, colours) can be passed. It is decorative (aria-hidden):
// the control around it carries the accessible name.
func icon(name string, class ...string) template.HTML {
	d, ok := iconPaths[name]
	if !ok {
		d = iconPaths["question"]
	}
	cls := "size-4"
	if len(class) > 0 {
		cls = class[0]
	}
	return template.HTML(fmt.Sprintf(`<svg class="inline-block shrink-0 %s" viewBox="0 0 24 24" fill="none" `+
		`stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">`+
		`<path d="%s"/></svg>`, template.HTMLEscapeString(cls), d))
}
