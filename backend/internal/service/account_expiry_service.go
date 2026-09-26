package service

import (
	"context"
	"log"
	"time"
)

// AccountExpiryService periodically pauses expired accounts when auto-pause is enabled.
type AccountExpiryService struct {
	accountRepo AccountRepository
	runner      *periodicRunner
}

func NewAccountExpiryService(accountRepo AccountRepository, interval time.Duration) *AccountExpiryService {
	s := &AccountExpiryService{accountRepo: accountRepo}
	s.runner = newPeriodicRunner(interval, s.runOnce)
	return s
}

func (s *AccountExpiryService) Start() {
	if s == nil || s.accountRepo == nil {
		return
	}
	s.runner.Start()
}

func (s *AccountExpiryService) Stop() {
	if s == nil {
		return
	}
	s.runner.Stop()
}

func (s *AccountExpiryService) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updated, err := s.accountRepo.AutoPauseExpiredAccounts(ctx, time.Now())
	if err != nil {
		log.Printf("[AccountExpiry] Auto pause expired accounts failed: %v", err)
		return
	}
	if updated > 0 {
		log.Printf("[AccountExpiry] Auto paused %d expired accounts", updated)
	}
}
