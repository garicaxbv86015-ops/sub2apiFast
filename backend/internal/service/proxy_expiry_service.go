package service

import (
	"context"
	"log"
	"time"
)

// ProxyExpiryService 周期扫描到期代理并把绑定账号改投备用/直连。
type ProxyExpiryService struct {
	proxyRepo ProxyRepository
	runner    *periodicRunner
}

func NewProxyExpiryService(proxyRepo ProxyRepository, interval time.Duration) *ProxyExpiryService {
	s := &ProxyExpiryService{proxyRepo: proxyRepo}
	s.runner = newPeriodicRunner(interval, s.runOnce)
	return s
}

func (s *ProxyExpiryService) Start() {
	if s == nil || s.proxyRepo == nil {
		return
	}
	s.runner.Start()
}

func (s *ProxyExpiryService) Stop() {
	if s == nil {
		return
	}
	s.runner.Stop()
}

func (s *ProxyExpiryService) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	changed, err := s.proxyRepo.SweepExpiredProxies(ctx, time.Now())
	if err != nil {
		log.Printf("[ProxyExpiry] sweep expired proxies failed: %v", err)
		return
	}
	if changed > 0 {
		log.Printf("[ProxyExpiry] re-routed %d accounts off expired proxies", changed)
	}
}
