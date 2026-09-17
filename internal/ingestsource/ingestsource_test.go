package ingestsource

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordingSink struct {
	mu       sync.Mutex
	accepted []string
}

func (r *recordingSink) Accept(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accepted = append(r.accepted, path)
	return nil
}

func (r *recordingSink) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.accepted))
	copy(out, r.accepted)
	return out
}

func TestFileWatchEventSource_IgnoresPreexistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.txt"), []byte("x"), 0644); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	src := &FileWatchEventSource{Dir: dir, Interval: 20 * time.Millisecond}
	sink := &recordingSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = src.Run(ctx, sink)

	if got := sink.snapshot(); len(got) != 0 {
		t.Errorf("accepted = %v, want ningún archivo preexistente reingerido", got)
	}
}

func TestFileWatchEventSource_DetectsNewFile(t *testing.T) {
	dir := t.TempDir()
	src := &FileWatchEventSource{Dir: dir, Interval: 20 * time.Millisecond}
	sink := &recordingSink{}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, sink) }()

	time.Sleep(50 * time.Millisecond)
	newFile := filepath.Join(dir, "new.json")
	if err := os.WriteFile(newFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("write new file: %v", err)
	}

	<-done
	got := sink.snapshot()
	if len(got) != 1 || got[0] != newFile {
		t.Errorf("accepted = %v, want [%s]", got, newFile)
	}
}

func TestFileWatchEventSource_NeverAcceptsSameFileTwice(t *testing.T) {
	dir := t.TempDir()
	src := &FileWatchEventSource{Dir: dir, Interval: 10 * time.Millisecond}
	sink := &recordingSink{}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, sink) }()

	time.Sleep(30 * time.Millisecond)
	f := filepath.Join(dir, "one.json")
	os.WriteFile(f, []byte("{}"), 0644)

	<-done
	got := sink.snapshot()
	count := 0
	for _, p := range got {
		if p == f {
			count++
		}
	}
	if count != 1 {
		t.Errorf("archivo aceptado %d veces, want 1", count)
	}
}
