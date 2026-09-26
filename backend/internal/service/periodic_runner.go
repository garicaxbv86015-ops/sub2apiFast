package service

import (
	"sync"
	"time"
)

// periodicRunner runs a function once immediately and then on a fixed interval
// until stopped. It encapsulates the ticker/goroutine lifecycle shared by the
// background sweep services.
type periodicRunner struct {
	interval time.Duration
	run      func()
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// newPeriodicRunner creates a runner that invokes run every interval. A nil run
// or a non-positive interval yields a runner whose Start is a no-op.
func newPeriodicRunner(interval time.Duration, run func()) *periodicRunner {
	return &periodicRunner{
		interval: interval,
		run:      run,
		stopCh:   make(chan struct{}),
	}
}

// Start launches the background loop. It runs once immediately, then on each
// tick, until Stop is called.
func (r *periodicRunner) Start() {
	if r == nil || r.run == nil || r.interval <= 0 {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		r.run()
		for {
			select {
			case <-ticker.C:
				r.run()
			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop signals the loop to exit and waits for it to finish. It is safe to call
// multiple times.
func (r *periodicRunner) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
	r.wg.Wait()
}
