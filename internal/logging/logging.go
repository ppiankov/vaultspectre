package logging

import (
	"io"
	"log/slog"
	"os"
)

// Init configures the global slog logger with output to stderr.
// verbose=true sets LevelDebug, verbose=false sets LevelWarn.
func Init(verbose bool) {
	InitTo(os.Stderr, verbose)
}

// InitTo configures the global slog logger with a custom writer.
func InitTo(w io.Writer, verbose bool) {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time for cleaner CLI output
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(handler))
}
