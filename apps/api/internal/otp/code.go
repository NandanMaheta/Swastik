package otp

import "io"

// GenerateCode returns 6 uniformly random digits read from r (rejection sampling).
func GenerateCode(_ io.Reader) (string, error) { return "", errNotImplemented }
