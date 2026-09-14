package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
)

//go:embed mirasim_core.wasm
var mirasimWasmBytes []byte

// MirasimSealPublicKey 是 Mirasim 官方中继元数据封套公钥（Base64）。
const MirasimSealPublicKey = "HlyNMMeGXryasYLJuYQ/9ksCD4AYVVy1zXKAtJdpJn4="

// MirasimSealPrefix 是元数据封套前缀。
const MirasimSealPrefix = "mrs-seal-v1"

// MirasimSigner 提供基于 Mirasim WebAssembly 核心的签名与元数据封套能力。
type MirasimSigner struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	initOnce sync.Once
	initErr  error
	counter  uint64
}

var (
	defaultMirasimSigner     *MirasimSigner
	defaultMirasimSignerOnce sync.Once
)

// GetMirasimSigner 获取全局单例 MirasimSigner 实例。
func GetMirasimSigner() (*MirasimSigner, error) {
	var err error
	defaultMirasimSignerOnce.Do(func() {
		defaultMirasimSigner = &MirasimSigner{}
		err = defaultMirasimSigner.init()
	})
	if err != nil {
		return nil, err
	}
	return defaultMirasimSigner, nil
}

// init 初始化 wazero 运行时并编译 WASM 字节码。
func (s *MirasimSigner) init() error {
	s.initOnce.Do(func() {
		ctx := context.Background()
		s.runtime = wazero.NewRuntime(ctx)
		compiled, err := s.runtime.CompileModule(ctx, mirasimWasmBytes)
		if err != nil {
			s.initErr = fmt.Errorf("compile mirasim wasm core failed: %w", err)
			return
		}
		s.compiled = compiled
	})
	return s.initErr
}

// DeriveDeviceID 根据 Base64 编码的公钥计算 22 字符的 Device ID。
// 步骤：计算 SHA-256 哈希，转换为 base64url 编码，截取前 22 字符。
func DeriveDeviceID(publicKeyB64 string) string {
	sum := sha256.Sum256([]byte(publicKeyB64))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(encoded) > 22 {
		return encoded[:22]
	}
	return encoded
}

// DerivePublicKey 使用 32 字节私钥种子调用 WASM 计算 Ed25519 公钥（32 字节）。
// 参数：
//   - ctx: 上下文
//   - seed: 32 字节 Ed25519 种子
// 返回值：
//   - []byte: 32 字节公钥
//   - error: 错误信息
func (s *MirasimSigner) DerivePublicKey(ctx context.Context, seed []byte) ([]byte, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("mirasim seed must be exactly 32 bytes, got %d", len(seed))
	}

	instanceName := fmt.Sprintf("mirasim_pub_%d", atomic.AddUint64(&s.counter, 1))
	mod, err := s.runtime.InstantiateModule(ctx, s.compiled, wazero.NewModuleConfig().WithName(instanceName))
	if err != nil {
		return nil, fmt.Errorf("instantiate wasm module failed: %w", err)
	}
	defer func() { _ = mod.Close(ctx) }()

	ccAlloc := mod.ExportedFunction("cc_alloc")
	ccFree := mod.ExportedFunction("cc_free")
	ccEd25519Pub := mod.ExportedFunction("cc_ed25519_pub")
	mem := mod.Memory()

	// 步骤 1: 写入 seed 到 WASM 线性内存
	pSeedRes, err := ccAlloc.Call(ctx, uint64(len(seed)))
	if err != nil {
		return nil, fmt.Errorf("cc_alloc failed: %w", err)
	}
	pSeed := uint32(pSeedRes[0])
	mem.Write(pSeed, seed)
	defer func() { _, _ = ccFree.Call(ctx, uint64(pSeed), uint64(len(seed))) }()

	// 步骤 2: 调用 cc_ed25519_pub
	res, err := ccEd25519Pub.Call(ctx, uint64(pSeed), uint64(len(seed)))
	if err != nil {
		return nil, fmt.Errorf("cc_ed25519_pub call failed: %w", err)
	}

	// 步骤 3: 读取返回值（高 32 位为指针，低 32 位为长度）
	val := res[0]
	ptr := uint32(val >> 32)
	length := uint32(val & 0xffffffff)
	if ptr == 0 || length == 0 {
		return nil, fmt.Errorf("cc_ed25519_pub returned null pointer")
	}

	data, ok := mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("failed to read memory from wasm")
	}
	out := make([]byte, length)
	copy(out, data)
	_, _ = ccFree.Call(ctx, uint64(ptr), uint64(length))

	return out, nil
}

// SignRelay 调用 WASM 核心计算 Mirasim 请求签名。
// 参数：
//   - ctx: 上下文
//   - seed: 32 字节私钥种子
//   - method: HTTP 请求方法，如 POST、GET
//   - path: 请求路径，如 /v1/chat/completions
//   - ts: 毫秒级时间戳字符串
//   - nonce: 随机 Nonce（12 字节 base64url）
//   - deviceID: 设备标识符
//   - clientVersion: 客户端版本号（如 0.0.322）
//   - credential: 凭据字符串（ticket 或 token）
//   - extraMeta: 额外元数据头映射表（用于排序拼接）
//   - body: 请求体字节切片
// 返回值：
//   - string: Base64URL 格式的 64 字节 Ed25519 签名
//   - error: 错误信息
func (s *MirasimSigner) SignRelay(
	ctx context.Context,
	seed []byte,
	method string,
	path string,
	ts string,
	nonce string,
	deviceID string,
	clientVersion string,
	credential string,
	extraMeta map[string]string,
	body []byte,
) (string, error) {
	if err := s.init(); err != nil {
		return "", err
	}
	if len(seed) != 32 {
		return "", fmt.Errorf("mirasim seed must be exactly 32 bytes, got %d", len(seed))
	}

	instanceName := fmt.Sprintf("mirasim_sign_%d", atomic.AddUint64(&s.counter, 1))
	mod, err := s.runtime.InstantiateModule(ctx, s.compiled, wazero.NewModuleConfig().WithName(instanceName))
	if err != nil {
		return "", fmt.Errorf("instantiate wasm module failed: %w", err)
	}
	defer func() { _ = mod.Close(ctx) }()

	ccAlloc := mod.ExportedFunction("cc_alloc")
	ccFree := mod.ExportedFunction("cc_free")
	ccSign := mod.ExportedFunction("cc_sign")
	mem := mod.Memory()

	allocAndWrite := func(data []byte) (uint32, uint32, error) {
		res, err := ccAlloc.Call(ctx, uint64(len(data)))
		if err != nil {
			return 0, 0, err
		}
		ptr := uint32(res[0])
		if len(data) > 0 {
			mem.Write(ptr, data)
		}
		return ptr, uint32(len(data)), nil
	}

	// 步骤 1: 构造规范化字符串（方法、路径、时间戳、nonce、设备ID、客户端版本、凭证，以 \x00 分隔）
	canonicalParts := []string{
		strings.ToUpper(strings.TrimSpace(method)),
		strings.TrimSpace(path),
		strings.TrimSpace(ts),
		strings.TrimSpace(nonce),
		strings.TrimSpace(deviceID),
		strings.TrimSpace(clientVersion),
		strings.TrimSpace(credential),
	}
	canonicalBytes := []byte(strings.Join(canonicalParts, "\x00"))

	// 步骤 2: 构造 extra headers 字符串（若有）
	var metaBytes []byte
	if len(extraMeta) > 0 {
		var metaParts []string
		for k, v := range extraMeta {
			if strings.TrimSpace(v) != "" {
				metaParts = append(metaParts, k, v)
			}
		}
		if len(metaParts) > 0 {
			metaBytes = []byte(strings.Join(metaParts, "\x00"))
		}
	}

	// 步骤 3: 内存分配并写入参数
	pSeed, lSeed, err := allocAndWrite(seed)
	if err != nil {
		return "", fmt.Errorf("alloc seed: %w", err)
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pSeed), uint64(lSeed)) }()

	pCanon, lCanon, err := allocAndWrite(canonicalBytes)
	if err != nil {
		return "", fmt.Errorf("alloc canonical: %w", err)
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pCanon), uint64(lCanon)) }()

	pMeta, lMeta, err := allocAndWrite(metaBytes)
	if err != nil {
		return "", fmt.Errorf("alloc meta: %w", err)
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pMeta), uint64(lMeta)) }()

	pBody, lBody, err := allocAndWrite(body)
	if err != nil {
		return "", fmt.Errorf("alloc body: %w", err)
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pBody), uint64(lBody)) }()

	// 步骤 4: 调用 cc_sign 获得签名
	res, err := ccSign.Call(ctx,
		uint64(pSeed), uint64(lSeed),
		uint64(pCanon), uint64(lCanon),
		uint64(pMeta), uint64(lMeta),
		uint64(pBody), uint64(lBody),
	)
	if err != nil {
		return "", fmt.Errorf("cc_sign call failed: %w", err)
	}

	val := res[0]
	ptr := uint32(val >> 32)
	length := uint32(val & 0xffffffff)
	if ptr == 0 || length == 0 {
		return "", fmt.Errorf("cc_sign returned empty signature")
	}

	sigBytes, ok := mem.Read(ptr, length)
	if !ok {
		return "", fmt.Errorf("failed to read signature memory")
	}
	out := make([]byte, length)
	copy(out, sigBytes)
	_, _ = ccFree.Call(ctx, uint64(ptr), uint64(length))

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// SealMetadata 调用 WASM 核心封套 x-mirasim-* 元数据。
// 参数：
//   - ctx: 上下文
//   - metaJsonBytes: JSON 格式的元数据字节切片
//   - method: HTTP 请求方法
//   - path: 请求路径
// 返回值：
//   - string: Base64URL 格式的封套数据（对应 x-mirasim-enc）
//   - error: 错误信息
func (s *MirasimSigner) SealMetadata(ctx context.Context, metaJsonBytes []byte, method, path string) (string, error) {
	if err := s.init(); err != nil {
		return "", err
	}

	sealPubkey, err := base64.StdEncoding.DecodeString(MirasimSealPublicKey)
	if err != nil {
		return "", fmt.Errorf("decode seal pubkey: %w", err)
	}

	rnd32 := make([]byte, 32)
	if _, err := rand.Read(rnd32); err != nil {
		return "", fmt.Errorf("generate rnd32: %w", err)
	}
	rnd12 := make([]byte, 12)
	if _, err := rand.Read(rnd12); err != nil {
		return "", fmt.Errorf("generate rnd12: %w", err)
	}

	prefix := []byte(fmt.Sprintf("%s\n%s\n%s", MirasimSealPrefix, strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path)))

	instanceName := fmt.Sprintf("mirasim_seal_%d", atomic.AddUint64(&s.counter, 1))
	mod, err := s.runtime.InstantiateModule(ctx, s.compiled, wazero.NewModuleConfig().WithName(instanceName))
	if err != nil {
		return "", fmt.Errorf("instantiate wasm module failed: %w", err)
	}
	defer func() { _ = mod.Close(ctx) }()

	ccAlloc := mod.ExportedFunction("cc_alloc")
	ccFree := mod.ExportedFunction("cc_free")
	ccSeal := mod.ExportedFunction("cc_seal")
	mem := mod.Memory()

	allocAndWrite := func(data []byte) (uint32, uint32, error) {
		res, err := ccAlloc.Call(ctx, uint64(len(data)))
		if err != nil {
			return 0, 0, err
		}
		ptr := uint32(res[0])
		if len(data) > 0 {
			mem.Write(ptr, data)
		}
		return ptr, uint32(len(data)), nil
	}

	pKey, lKey, err := allocAndWrite(sealPubkey)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pKey), uint64(lKey)) }()

	pR32, lR32, err := allocAndWrite(rnd32)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pR32), uint64(lR32)) }()

	pR12, lR12, err := allocAndWrite(rnd12)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pR12), uint64(lR12)) }()

	pData, lData, err := allocAndWrite(metaJsonBytes)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pData), uint64(lData)) }()

	pPrefix, lPrefix, err := allocAndWrite(prefix)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = ccFree.Call(ctx, uint64(pPrefix), uint64(lPrefix)) }()

	res, err := ccSeal.Call(ctx,
		uint64(pKey), uint64(lKey),
		uint64(pR32), uint64(lR32),
		uint64(pR12), uint64(lR12),
		uint64(pData), uint64(lData),
		uint64(pPrefix), uint64(lPrefix),
	)
	if err != nil {
		return "", fmt.Errorf("cc_seal call failed: %w", err)
	}

	val := res[0]
	ptr := uint32(val >> 32)
	length := uint32(val & 0xffffffff)
	if ptr == 0 || length == 0 {
		return "", fmt.Errorf("cc_seal returned empty output")
	}

	sealedBytes, ok := mem.Read(ptr, length)
	if !ok {
		return "", fmt.Errorf("failed to read seal memory")
	}
	out := make([]byte, length)
	copy(out, sealedBytes)
	_, _ = ccFree.Call(ctx, uint64(ptr), uint64(length))

	return base64.RawURLEncoding.EncodeToString(out), nil
}
