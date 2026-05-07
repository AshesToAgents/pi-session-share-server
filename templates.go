package main

import (
	_ "embed"
	"strings"

	"github.com/yuin/goldmark"
)

//go:embed templates/password.html
var passwordHTML string

//go:embed templates/error.html
var errorHTML string

//go:embed README.md
var readmeMarkdown string

// readmeHTML is the README rendered as HTML at startup.
var readmeHTML []byte

func init() {
	var buf strings.Builder
	if err := goldmark.Convert([]byte(readmeMarkdown), &buf); err != nil {
		panic("failed to render README: " + err.Error())
	}
	readmeHTML = []byte(wrapReadmeHTML(buf.String()))
}

func wrapReadmeHTML(body string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pi-session-share-server</title>
<style>
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 40px 20px;
    color: #1a1a2e;
    line-height: 1.6;
}
h1, h2, h3 { color: #1a1a2e; }
h1 { border-bottom: 2px solid #667eea; padding-bottom: 8px; }
h2 { border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; margin-top: 2em; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
pre { background: #f3f4f6; padding: 16px; border-radius: 8px; overflow-x: auto; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }
th { background: #f9fafb; }
a { color: #667eea; }
blockquote { border-left: 4px solid #667eea; margin: 1em 0; padding: 0.5em 1em; background: #f9fafb; }
</style>
</head>
<body>
` + body + `
</body>
</html>`
}
