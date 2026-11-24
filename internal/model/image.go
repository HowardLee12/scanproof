package model

import "strings"

// ImageName drops the tag and digest from an image reference, so builds of
// the same image can be compared with each other.
func ImageName(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	slash := strings.LastIndex(name, "/")
	if colon := strings.LastIndex(name, ":"); colon > slash {
		name = name[:colon]
	}
	return name
}

// DigestOf returns the digest pinned in a reference such as repo@sha256:...,
// or "" when the reference has none.
func DigestOf(ref string) string {
	_, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return ""
	}
	return digest
}
