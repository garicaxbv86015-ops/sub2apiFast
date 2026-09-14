package mirasim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func encryptTestMrs1(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tag := sealed[len(plaintext):]
	ct := sealed[:len(plaintext)]

	buf := append(iv, tag...)
	buf = append(buf, ct...)
	return "mrs1:" + base64.StdEncoding.EncodeToString(buf), nil
}

func TestDecryptMrs1Payload(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-secret"
	encrypted, err := encryptTestMrs1(key, []byte(plaintext))
	require.NoError(t, err)

	decrypted, err := DecryptMrs1Payload(encrypted, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// Non-encrypted string should pass through unchanged
	raw := "normal-unencrypted-token"
	decryptedRaw, err := DecryptMrs1Payload(raw, key)
	require.NoError(t, err)
	require.Equal(t, raw, decryptedRaw)

	// SetMasterKey & DecryptMrs1String
	SetMasterKey(key)
	decAuto, err := DecryptMrs1String(encrypted)
	require.NoError(t, err)
	require.Equal(t, plaintext, decAuto)
}

func TestGetMasterKeyFromEnv(t *testing.T) {
	dummyKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("MIRASIM_SECRET_KEY", dummyKeyHex)

	masterKeyMu.Lock()
	cachedMasterKey = nil
	masterKeyMu.Unlock()

	key, err := GetMasterKey()
	require.NoError(t, err)
	require.Equal(t, dummyKeyHex, hex.EncodeToString(key))
}

func TestGetMasterKeyFromKeychain(t *testing.T) {
	masterKeyMu.Lock()
	cachedMasterKey = nil
	masterKeyMu.Unlock()

	t.Setenv("MIRASIM_SECRET_KEY", "")
	t.Setenv("SECRET_KEY", "")
	t.Setenv("APP_SECRET_KEY", "")

	key, err := GetMasterKey()
	if err != nil {
		t.Skipf("Keychain not accessible in this environment: %v", err)
	}
	require.Len(t, key, 32)
	t.Logf("Successfully retrieved master key from keychain, length: %d", len(key))
}

func TestDecryptLocalSetting(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	settingPath := filepath.Join(homeDir, ".mirasim", "setting.json")
	data, err := os.ReadFile(settingPath)
	if err != nil {
		t.Skipf("No local setting.json: %v", err)
	}

	var parsed struct {
		Auth struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refreshToken"`
		} `json:"auth"`
		Device struct {
			PrivateKey string `json:"privateKey"`
		} `json:"device"`
	}
	require.NoError(t, json.Unmarshal(data, &parsed))

	decToken, err := DecryptMrs1String(parsed.Auth.Token)
	require.NoError(t, err)
	t.Logf("Decrypted token length: %d, isMrs1: %v", len(decToken), strings.HasPrefix(parsed.Auth.Token, "mrs1:"))

	decPriv, err := DecryptMrs1String(parsed.Device.PrivateKey)
	require.NoError(t, err)
	t.Logf("Decrypted private key length: %d, isMrs1: %v", len(decPriv), strings.HasPrefix(parsed.Device.PrivateKey, "mrs1:"))
}
