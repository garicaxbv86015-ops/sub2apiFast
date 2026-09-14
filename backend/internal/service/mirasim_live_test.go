package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func decryptMrs1(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "mrs1:") {
		return ciphertext, nil
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", "mirasim", "-a", "config-secret-key", "-w").Output()
	if err != nil {
		return "", err
	}
	masterHex := strings.TrimSpace(string(out))
	masterKey, err := hex.DecodeString(masterHex)
	if err != nil {
		return "", err
	}

	raw, err := base64.StdEncoding.DecodeString(ciphertext[len("mrs1:"):])
	if err != nil {
		return "", err
	}

	if len(raw) < 12+16 {
		return "", io.ErrUnexpectedEOF
	}
	iv := raw[:12]
	tag := raw[12 : 12+16]
	data := raw[12+16:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return "", err
	}

	ciphertextWithTag := append(data, tag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func TestMirasimLimitsCalls(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	settingFile := filepath.Join(homeDir, ".mirasim", "setting.json")
	settingBytes, err := os.ReadFile(settingFile)
	require.NoError(t, err)

	var settingData struct {
		Auth struct {
			Token string `json:"token"`
		} `json:"auth"`
		Device struct {
			PrivateKey string `json:"privateKey"`
		} `json:"device"`
	}
	err = json.Unmarshal(settingBytes, &settingData)
	require.NoError(t, err)

	token, err := decryptMrs1(settingData.Auth.Token)
	require.NoError(t, err)
	privKeyPEM, err := decryptMrs1(settingData.Device.PrivateKey)
	require.NoError(t, err)

	seed, err := ParseEd25519Seed(privKeyPEM)
	require.NoError(t, err)

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	spkiBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	spkiB64 := base64.StdEncoding.EncodeToString(spkiBytes)

	h := sha256.Sum256([]byte(spkiB64))
	devID := base64.RawURLEncoding.EncodeToString(h[:])[:22]

	bodyObj := map[string]string{
		"publicKey": spkiB64,
		"deviceId":  devID,
	}
	bodyBytes, err := json.Marshal(bodyObj)
	require.NoError(t, err)

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	nonce := GenerateMirasimNonce()
	clientVersion := "0.0.322"

	signer, err := GetMirasimSigner()
	require.NoError(t, err)

	sig, err := signer.SignRelay(
		context.Background(),
		seed,
		http.MethodPost,
		"/v1/device/session",
		ts,
		nonce,
		devID,
		clientVersion,
		token,
		nil,
		bodyBytes,
	)
	require.NoError(t, err)

	mintURL := "https://relay.mirasim.ai/v1/device/session"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, mintURL, strings.NewReader(string(bodyBytes)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(headerMirasimDevice, devID)
	req.Header.Set(headerMirasimTS, ts)
	req.Header.Set(headerMirasimNonce, nonce)
	req.Header.Set(headerMirasimSig, sig)
	req.Header.Set(headerMirasimClient, clientVersion)

	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	var sessionResp struct {
		Ticket string `json:"ticket"`
	}
	err = json.Unmarshal(respBytes, &sessionResp)
	require.NoError(t, err)
	ticket := sessionResp.Ticket
	t.Logf("Minted ticket len: %d", len(ticket))

	// Test 1: Probe /v1/limits using ticket (WITHOUT signature)
	{
		r, _ := http.NewRequest(http.MethodGet, "https://relay.mirasim.ai/v1/limits", nil)
		r.Header.Set("Authorization", "Bearer "+ticket)
		r.Header.Set("x-mirasim-probe", "usage")
		res, err := cli.Do(r)
		require.NoError(t, err)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Logf("Test 1 (/v1/limits with ticket only): status=%d body=%s", res.StatusCode, string(b))
	}

	// Test 2: Probe /v1/limits using ticket WITH SIGNATURE
	{
		r, _ := http.NewRequest(http.MethodGet, "https://relay.mirasim.ai/v1/limits", nil)
		r.Header.Set("Authorization", "Bearer "+ticket)
		r.Header.Set("x-mirasim-probe", "usage")

		ts2 := fmt.Sprintf("%d", time.Now().UnixMilli())
		nonce2 := GenerateMirasimNonce()
		sig2, err := signer.SignRelay(
			context.Background(),
			seed,
			http.MethodGet,
			"/v1/limits",
			ts2,
			nonce2,
			devID,
			clientVersion,
			ticket,
			nil,
			nil,
		)
		require.NoError(t, err)
		r.Header.Set(headerMirasimDevice, devID)
		r.Header.Set(headerMirasimTS, ts2)
		r.Header.Set(headerMirasimNonce, nonce2)
		r.Header.Set(headerMirasimSig, sig2)
		r.Header.Set(headerMirasimClient, clientVersion)

		res, err := cli.Do(r)
		require.NoError(t, err)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Logf("Test 2 (/v1/limits with ticket AND signature): status=%d body=%s", res.StatusCode, string(b))
	}

	// Test 3: Probe /v1/limits using token only (WITHOUT ticket)
	{
		r, _ := http.NewRequest(http.MethodGet, "https://relay.mirasim.ai/v1/limits", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("x-mirasim-probe", "usage")
		res, err := cli.Do(r)
		require.NoError(t, err)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Logf("Test 3 (/v1/limits with token only): status=%d body=%s", res.StatusCode, string(b))
	}
}

// TestMirasimGPTResponsesProbe 探测 relay 是否支持 GPT 模型的原生 /v1/responses 协议。
// 凭据从环境变量读取（MIRA_TOKEN / MIRA_PRIV_KEY），使用数据库中账号 3 的最新凭据。
// 分别用 gpt-6-astra 打 /v1/responses 与 /v1/chat/completions，对比状态码判断协议可用性。
func TestMirasimGPTResponsesProbe(t *testing.T) {
	tokenBytes, err := os.ReadFile("/tmp/mira_token.txt")
	require.NoError(t, err)
	token := strings.TrimSpace(string(tokenBytes))
	keyBytes, err := os.ReadFile("/tmp/mira_key.txt")
	require.NoError(t, err)
	privKeyPEM := strings.TrimSpace(string(keyBytes))
	require.NotEmpty(t, token)
	require.NotEmpty(t, privKeyPEM)
	seed, err := ParseEd25519Seed(privKeyPEM)
	require.NoError(t, err)
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	spkiBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	spkiB64 := base64.StdEncoding.EncodeToString(spkiBytes)
	h := sha256.Sum256([]byte(spkiB64))
	devID := base64.RawURLEncoding.EncodeToString(h[:])[:22]

	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	cli := &http.Client{Timeout: 20 * time.Second}
	clientVersion := "0.0.322"

	// mint ticket
	bodyObj := map[string]string{"publicKey": spkiB64, "deviceId": devID}
	bodyBytes, _ := json.Marshal(bodyObj)
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	nonce := GenerateMirasimNonce()
	sig, err := signer.SignRelay(context.Background(), seed, http.MethodPost, "/v1/device/session", ts, nonce, devID, clientVersion, token, nil, bodyBytes)
	require.NoError(t, err)
	mreq, _ := http.NewRequest(http.MethodPost, "https://relay.mirasim.ai/v1/device/session", strings.NewReader(string(bodyBytes)))
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("Authorization", "Bearer "+token)
	mreq.Header.Set(headerMirasimDevice, devID)
	mreq.Header.Set(headerMirasimTS, ts)
	mreq.Header.Set(headerMirasimNonce, nonce)
	mreq.Header.Set(headerMirasimSig, sig)
	mreq.Header.Set(headerMirasimClient, clientVersion)
	mres, err := cli.Do(mreq)
	require.NoError(t, err)
	mb, _ := io.ReadAll(mres.Body)
	mres.Body.Close()
	ticket := gjson.GetBytes(mb, "ticket").String()
	require.NotEmpty(t, ticket, "mint ticket failed: %s", string(mb))
	t.Logf("minted ticket")

	doSigned := func(path string, payload []byte) (int, string) {
		ts := fmt.Sprintf("%d", time.Now().UnixMilli())
		nonce := GenerateMirasimNonce()
		sig, err := signer.SignRelay(context.Background(), seed, http.MethodPost, path, ts, nonce, devID, clientVersion, ticket, nil, payload)
		require.NoError(t, err)
		r, _ := http.NewRequest(http.MethodPost, "https://relay.mirasim.ai"+path, strings.NewReader(string(payload)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+ticket)
		r.Header.Set(headerMirasimDevice, devID)
		r.Header.Set(headerMirasimTS, ts)
		r.Header.Set(headerMirasimNonce, nonce)
		r.Header.Set(headerMirasimSig, sig)
		r.Header.Set(headerMirasimClient, clientVersion)
		res, err := cli.Do(r)
		require.NoError(t, err)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(b)
	}

	ccPayload := []byte(`{"model":"gpt-6-astra","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":16}`)
	st, body := doSigned("/v1/chat/completions", ccPayload)
	t.Logf("GPT /v1/chat/completions -> %d: %.400s", st, body)

	respPayload := []byte(`{"model":"gpt-6-astra","input":[{"role":"user","content":"hi"}],"stream":true,"max_output_tokens":16}`)
	st, body = doSigned("/v1/responses", respPayload)
	t.Logf("GPT /v1/responses -> %d: %.400s", st, body)
}

// TestMirasimLimitsRaw 打印 /v1/limits 原始响应，确认窗口 name/budget/used/reset_at 字段。
func TestMirasimLimitsRaw(t *testing.T) {
	tokenBytes, err := os.ReadFile("/tmp/mira_token.txt")
	require.NoError(t, err)
	token := strings.TrimSpace(string(tokenBytes))
	seedBytes, err := os.ReadFile("/tmp/mira_seed.txt")
	require.NoError(t, err)
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedBytes)))
	require.NoError(t, err)
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	spkiBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	spkiB64 := base64.StdEncoding.EncodeToString(spkiBytes)
	h := sha256.Sum256([]byte(spkiB64))
	devID := base64.RawURLEncoding.EncodeToString(h[:])[:22]

	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	cli := &http.Client{Timeout: 20 * time.Second}
	clientVersion := "0.0.322"

	bodyObj := map[string]string{"publicKey": spkiB64, "deviceId": devID}
	bodyBytes, _ := json.Marshal(bodyObj)
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	nonce := GenerateMirasimNonce()
	sig, err := signer.SignRelay(context.Background(), seed, http.MethodPost, "/v1/device/session", ts, nonce, devID, clientVersion, token, nil, bodyBytes)
	require.NoError(t, err)
	mreq, _ := http.NewRequest(http.MethodPost, "https://relay.mirasim.ai/v1/device/session", strings.NewReader(string(bodyBytes)))
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("Authorization", "Bearer "+token)
	mreq.Header.Set(headerMirasimDevice, devID)
	mreq.Header.Set(headerMirasimTS, ts)
	mreq.Header.Set(headerMirasimNonce, nonce)
	mreq.Header.Set(headerMirasimSig, sig)
	mreq.Header.Set(headerMirasimClient, clientVersion)
	mres, err := cli.Do(mreq)
	require.NoError(t, err)
	mb, _ := io.ReadAll(mres.Body)
	mres.Body.Close()
	ticket := gjson.GetBytes(mb, "ticket").String()
	require.NotEmpty(t, ticket, "mint ticket failed: %s", string(mb))

	ts2 := fmt.Sprintf("%d", time.Now().UnixMilli())
	nonce2 := GenerateMirasimNonce()
	sig2, err := signer.SignRelay(context.Background(), seed, http.MethodGet, "/v1/limits", ts2, nonce2, devID, clientVersion, ticket, nil, nil)
	require.NoError(t, err)
	r, _ := http.NewRequest(http.MethodGet, "https://relay.mirasim.ai/v1/limits", nil)
	r.Header.Set("Authorization", "Bearer "+ticket)
	r.Header.Set("x-mirasim-probe", "usage")
	r.Header.Set(headerMirasimDevice, devID)
	r.Header.Set(headerMirasimTS, ts2)
	r.Header.Set(headerMirasimNonce, nonce2)
	r.Header.Set(headerMirasimSig, sig2)
	r.Header.Set(headerMirasimClient, clientVersion)
	res, err := cli.Do(r)
	require.NoError(t, err)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	t.Logf("/v1/limits -> %d:\n%s", res.StatusCode, string(b))
}
