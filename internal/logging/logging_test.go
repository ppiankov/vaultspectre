package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestInit_Verbose(t *testing.T) {
	Init(true)
	ctx := context.Background()
	if !slog.Default().Enabled(ctx, slog.LevelDebug) {
		t.Error("verbose=true should enable debug level")
	}
	if !slog.Default().Enabled(ctx, slog.LevelInfo) {
		t.Error("verbose=true should enable info level")
	}
	if !slog.Default().Enabled(ctx, slog.LevelWarn) {
		t.Error("verbose=true should enable warn level")
	}
}

func TestInit_Default(t *testing.T) {
	Init(false)
	ctx := context.Background()
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		t.Error("verbose=false should not enable debug level")
	}
	if slog.Default().Enabled(ctx, slog.LevelInfo) {
		t.Error("verbose=false should not enable info level")
	}
	if !slog.Default().Enabled(ctx, slog.LevelWarn) {
		t.Error("verbose=false should enable warn level")
	}
	if !slog.Default().Enabled(ctx, slog.LevelError) {
		t.Error("verbose=false should enable error level")
	}
}

func TestInitTo_Output(t *testing.T) {
	var buf bytes.Buffer
	InitTo(&buf, true)
	slog.Info("test message", "key", "value")
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected output to contain 'key=value', got: %s", output)
	}
}

func TestInitTo_NoTime(t *testing.T) {
	var buf bytes.Buffer
	InitTo(&buf, true)
	slog.Info("test")
	output := buf.String()
	if strings.Contains(output, "time=") {
		t.Errorf("expected no time field, got: %s", output)
	}
}

func TestInitTo_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	InitTo(&buf, false)
	slog.Debug("should not appear")
	slog.Info("should not appear")
	if buf.Len() > 0 {
		t.Errorf("expected no output for debug/info with verbose=false, got: %s", buf.String())
	}

	slog.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("expected warn to appear with verbose=false, got: %s", buf.String())
	}
}
