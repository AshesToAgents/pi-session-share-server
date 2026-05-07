package main

import (
	_ "embed"
	"strings"
)

//go:embed templates/password.html
var passwordHTML string

//go:embed templates/error.html
var errorHTML string

// GetPasswordHTML returns the password form template.
func GetPasswordHTML() string {
	return passwordHTML
}

// GetErrorHTML returns the error page template.
func GetErrorHTML() string {
	return errorHTML
}

// ReplaceTemplateVar replaces a template variable like {{name}} with the value.
func ReplaceTemplateVar(html, name, value string) string {
	return strings.Replace(html, "{{"+name+"}}", value, -1)
}
