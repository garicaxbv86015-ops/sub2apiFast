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

// TestParseJWTSubject 覆盖含 sub 的无填充/已填充 JWT、缺 sub 的正常返回及非法输入；t 为测试上下文，无返回值。
func TestParseJWTSubject(t *testing.T) {
	// 含 sub：无填充与已填充编码均应解析出同一 sub。
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		sub, err := ParseJWTSubject("header." + encoding.EncodeToString([]byte(`{"sub":"user-42"}`)) + ".signature")
		require.NoError(t, err)
		require.Equal(t, "user-42", sub)
	}
	// 缺 sub：不报错，返回空串，交由调用方决定是否设置字段。
	sub, err := ParseJWTSubject("header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000000300}`)) + ".sig")
	require.NoError(t, err)
	require.Empty(t, sub)
	// 非法输入：报错。
	for _, token := range []string{"", "opaque", "header.%%%.sig", "header.bm90LWpzb24.sig"} {
		_, err := ParseJWTSubject(token)
		require.Error(t, err)
	}
}
