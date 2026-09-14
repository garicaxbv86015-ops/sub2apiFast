package mirasim

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	masterKeyMu    sync.RWMutex
	cachedMasterKey []byte
)

// SetMasterKey 显式设置 Mirasim 凭据解密主密钥（32 字节）。
// 参数：
//   - key: 32 字节主密钥切片
func SetMasterKey(key []byte) {
	masterKeyMu.Lock()
	defer masterKeyMu.Unlock()
	if len(key) == 32 {
		cachedMasterKey = make([]byte, 32)
		copy(cachedMasterKey, key)
	}
}

// GetMasterKey 获取 Mirasim 本地凭据解密所用的 32 字节主密钥。
// 按优先级依次尝试环境变量、系统钥匙串/凭证管理服务。
// 返回值：
//   - []byte: 32 字节主密钥
//   - error: 获取失败或未找到有效密钥
func GetMasterKey() ([]byte, error) {
	masterKeyMu.RLock()
	if len(cachedMasterKey) == 32 {
		key := make([]byte, 32)
		copy(key, cachedMasterKey)
		masterKeyMu.RUnlock()
		return key, nil
	}
	masterKeyMu.RUnlock()

	masterKeyMu.Lock()
	defer masterKeyMu.Unlock()
	if len(cachedMasterKey) == 32 {
		key := make([]byte, 32)
		copy(key, cachedMasterKey)
		return key, nil
	}

	// 步骤 1: 检查环境变量 MIRASIM_SECRET_KEY / SECRET_KEY / APP_SECRET_KEY
	for _, envName := range []string{"MIRASIM_SECRET_KEY", "SECRET_KEY", "APP_SECRET_KEY"} {
		if val := strings.TrimSpace(os.Getenv(envName)); len(val) == 64 {
			if keyBytes, err := hex.DecodeString(val); err == nil && len(keyBytes) == 32 {
				cachedMasterKey = keyBytes
				out := make([]byte, 32)
				copy(out, cachedMasterKey)
				return out, nil
			}
		}
	}

	// 步骤 2: 依据操作系统平台从系统凭证存储提取主密钥
	var keyHex string
	switch runtime.GOOS {
	case "darwin":
		// macOS: 通过 /usr/bin/security 查询系统钥匙串
		out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", "mirasim", "-a", "config-secret-key", "-w").Output()
		if err == nil {
			keyHex = strings.TrimSpace(string(out))
		}
	case "linux":
		// Linux: 通过 secret-tool 查询凭据
		out, err := exec.Command("secret-tool", "lookup", "service", "mirasim", "account", "config-secret-key").Output()
		if err == nil {
			keyHex = strings.TrimSpace(string(out))
		}
	case "windows":
		// Windows: 读取 ~/.mirasim/secret.key 并通过 DPAPI 解密
		homeDir, err := os.UserHomeDir()
		if err == nil {
			secKeyPath := filepath.Join(homeDir, ".mirasim", "secret.key")
			if secData, err := os.ReadFile(secKeyPath); err == nil {
				b64Str := strings.TrimSpace(string(secData))
				if b64Str != "" {
					psCmd := fmt.Sprintf(`Add-Type -AssemblyName System.Security; [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String('%s'), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))`, b64Str)
					out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psCmd).Output()
					if err == nil {
						keyHex = strings.TrimSpace(string(out))
					}
				}
			}
		}
	}

	if len(keyHex) == 64 {
		if keyBytes, err := hex.DecodeString(keyHex); err == nil && len(keyBytes) == 32 {
			cachedMasterKey = keyBytes
			out := make([]byte, 32)
			copy(out, cachedMasterKey)
			return out, nil
		}
	}

	return nil, errors.New("mirasim master secret key not found in env or system keyring")
}

// DecryptMrs1Payload 使用给定的 32 字节主密钥解密 mrs1: 格式的密文。
// 若输入未包含 mrs1: 前缀，则原样返回。
// 格式规范：
//   - 剥离 "mrs1:" 前缀后进行 Base64 解码
//   - 前 12 字节为 Nonce (IV)
//   - 后续 16 字节为 GCM Auth Tag
//   - 剩余字节为 AES-256-GCM 密文
// 参数：
//   - encryptedStr: 待解密字符串
//   - key: 32 字节主密钥
// 返回值：
//   - string: 解密后的明文字符串
//   - error: 解密失败时的错误
func DecryptMrs1Payload(encryptedStr string, key []byte) (string, error) {
	if !strings.HasPrefix(encryptedStr, "mrs1:") {
		return encryptedStr, nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}

	// 步骤 1: 剥离 mrs1: 并进行 base64 解码
	payloadB64 := strings.TrimPrefix(encryptedStr, "mrs1:")
	raw, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode mrs1 payload failed: %w", err)
	}

	// 步骤 2: 校验最小长度（12 字节 IV + 16 字节 Tag）
	if len(raw) < 28 {
		return "", fmt.Errorf("mrs1 payload too short: %d bytes (minimum 28)", len(raw))
	}

	iv := raw[:12]
	tag := raw[12:28]
	ciphertext := raw[28:]

	// 步骤 3: 构造 AES-256-GCM 并解密
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", fmt.Errorf("gcm mode creation failed: %w", err)
	}

	combined := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, combined, nil)
	if err != nil {
		return "", fmt.Errorf("gcm decrypt failed: %w", err)
	}

	return string(plaintext), nil
}

// DecryptMrs1String 自动尝试获取系统主密钥并解密 mrs1: 前缀的凭据字符串。
// 若非 mrs1: 前缀则直接原样返回。
// 参数：
//   - encryptedStr: 待解密字符串
// 返回值：
//   - string: 解密后的明文字符串
//   - error: 密钥获取或解密错误
func DecryptMrs1String(encryptedStr string) (string, error) {
	if !strings.HasPrefix(encryptedStr, "mrs1:") {
		return encryptedStr, nil
	}

	key, err := GetMasterKey()
	if err != nil {
		return "", fmt.Errorf("get mirasim master key: %w", err)
	}

	return DecryptMrs1Payload(encryptedStr, key)
}
