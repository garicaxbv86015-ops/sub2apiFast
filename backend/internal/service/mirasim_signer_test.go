package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMirasimSigner_DerivePublicKey(t *testing.T) {
	ctx := context.Background()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	derivedPub, err := signer.DerivePublicKey(ctx, priv.Seed())
	require.NoError(t, err)
	require.Equal(t, []byte(pub), derivedPub)

	// 测试 DeriveDeviceID
	b64Pub := base64.StdEncoding.EncodeToString(pub)
	devID := DeriveDeviceID(b64Pub)
	require.Len(t, devID, 22)
}

func TestMirasimSigner_SignRelay(t *testing.T) {
	ctx := context.Background()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)

	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	sig, err := signer.SignRelay(
		ctx,
		priv.Seed(),
		"POST",
		"/v1/chat/completions",
		"1726000000000",
		"testnonce123",
		"testdev456",
		"0.0.322",
		"ticket_abc",
		nil,
		[]byte(`{"model":"claude-opus-5"}`),
	)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// 签名经过 base64url 解码应为 64 字节
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	require.NoError(t, err)
	require.Len(t, sigBytes, 64)
}

func TestMirasimSigner_SealMetadata(t *testing.T) {
	ctx := context.Background()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)

	metaJSON := []byte(`{"session":"s1","agent":"claude"}`)
	sealed, err := signer.SealMetadata(ctx, metaJSON, "POST", "/v1/messages")
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	sealedBytes, err := base64.RawURLEncoding.DecodeString(sealed)
	require.NoError(t, err)
	require.NotEmpty(t, sealedBytes)
}
