package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokulapap/wappalyzer-cli/internal/command"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(command.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
