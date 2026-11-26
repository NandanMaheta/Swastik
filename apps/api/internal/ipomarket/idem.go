package ipomarket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// requestHash is the SHA-256 (hex) of the canonical request: the action plus every path and body
// value that decides the outcome (D-07).
func requestHash(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		b = []byte(fmt.Sprint(parts...))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func optKey(key string) *string {
	if key == "" {
		return nil
	}
	return &key
}

func derefInt32(p *int32) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefUUID(p *uuid.UUID) any {
	if p == nil {
		return nil
	}
	return p.String()
}
