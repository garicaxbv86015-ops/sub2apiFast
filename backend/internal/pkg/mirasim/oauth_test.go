package mirasim

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestGenerateEd25519DeviceKey 测试自动生成设备密钥与设备 ID
func TestGenerateEd25519DeviceKey(t *testing.T) {
	privPEM, pubKeyB64, deviceID, err := GenerateEd25519DeviceKey()
	if err != nil {
		t.Fatalf("GenerateEd25519DeviceKey failed: %v", err)
	}

	if privPEM == "" {
		t.Fatal("expected non-empty privPEM")
	}
	if pubKeyB64 == "" {
		t.Fatal("expected non-empty pubKeyB64")
	}
	if len(deviceID) != 22 {
		t.Fatalf("expected 22-char deviceID, got %d (%s)", len(deviceID), deviceID)
	}

	// 校验 PEM 可被标准 x509 解析
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode pem block")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse pkcs8: %v", err)
	}
	edPriv, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not ed25519")
	}
	if len(edPriv.Seed()) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(edPriv.Seed()))
	}
}

// TestParseAuthorizationInput 测试解析各种输入回调格式
func TestParseAuthorizationInput(t *testing.T) {
	// 测试完整 URL
	u := "http://localhost:8085/callback?access_token=tok123&refresh_token=ref456&state=st789"
	res := ParseAuthorizationInput(u)
	if res.AccessToken != "tok123" || res.RefreshToken != "ref456" || res.State != "st789" {
		t.Fatalf("unexpected parse from URL: %+v", res)
	}

	// 测试纯 token
	raw := "eyJhbGciOiJIUzI1NiJ9.test"
	res2 := ParseAuthorizationInput(raw)
	if res2.AccessToken != raw {
		t.Fatalf("unexpected parse from raw token: %+v", res2)
	}

	// 测试查询参数字符串
	q := "token=my_tok&refresh_token=my_ref"
	res3 := ParseAuthorizationInput(q)
	if res3.AccessToken != "my_tok" || res3.RefreshToken != "my_ref" {
		t.Fatalf("unexpected parse from query string: %+v", res3)
	}
}

// TestSessionStore 测试会话存储存取与超时
func TestSessionStore(t *testing.T) {
	store := NewSessionStore()
	defer store.Stop()

	sess := &OAuthSession{
		State:       "state123",
		Provider:    "github",
		RedirectURI: "http://localhost:8085/callback",
		CreatedAt:   time.Now(),
	}

	store.Set("sess1", sess)
	got, ok := store.Get("sess1")
	if !ok || got.State != "state123" {
		t.Fatalf("expected to get sess1, got %+v, ok=%v", got, ok)
	}

	store.Delete("sess1")
	_, ok = store.Get("sess1")
	if ok {
		t.Fatal("expected sess1 to be deleted")
	}
}
