package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vietanhduong/go-tracing/pkg/loader"
	"github.com/vietanhduong/go-tracing/pkg/logging"
	"github.com/vietanhduong/go-tracing/pkg/tracing"
)

func RootCmd() *cobra.Command {
	v := viper.New()
	cmd := &cobra.Command{
		Use: "tracing",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGKILL)
			defer cancel()
			logging.SetupLoggingWithViper(v)

			loader := loader.InitFromViper(v)
			tracer := tracing.InitWithViper(tracing.Args{Loader: loader}, v)
			if err := tracer.Init(ctx); err != nil {
				return fmt.Errorf("failed to init tracer: %w", err)
			}
			defer tracer.Close()
			return tracer.Run(ctx)
		},
	}
	addFlags(v, cmd, tracing.RegisterFlags, loader.RegisterFlags, logging.RegisterFlags)
	return cmd
}
