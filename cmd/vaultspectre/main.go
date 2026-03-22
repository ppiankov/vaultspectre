package main

import (
	"fmt"
	"os"

	"github.com/ppiankov/vaultspectre/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(commands.ExitCodeFromError(err))
	}
}
