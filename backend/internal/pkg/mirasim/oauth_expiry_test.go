package mirasim

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseJWTExpiresAtPadding 覆盖不同长度的无填充 JWT、已填充 JWT 和非法输入；t 为测试上下文，无返回值。
func TestParseJWTExpiresAtPadding(t *testing.T) {
	for _, payload := range []string{`{"exp":2000000300}`, `{"exp":2000000300 }`, `{"exp":2000000300  }`} {
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
			exp, err := ParseJWTExpiresAt("header."+encoding.EncodeToString([]byte(payload))+".signature")
			require.NoError(t, err)
			require.Equal(t, int64(2000000300), exp)
		}
	}
	for _, token := range []string{"", "opaque", "header.x.sig", "header.%%%.sig", "header.bm90LWpzb24.sig"} {
		_, err := ParseJWTExpiresAt(token)
		require.Error(t, err)
	}
}
