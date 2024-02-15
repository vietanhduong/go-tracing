package main

import (
	"flag"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addFlags(v *viper.Viper, command *cobra.Command, inits ...func(*flag.FlagSet)) (*viper.Viper, *cobra.Command) {
	flagSet := new(flag.FlagSet)
	for i := range inits {
		inits[i](flagSet)
	}
	command.Flags().AddGoFlagSet(flagSet)

	configureViper(v)
	v.BindPFlags(command.Flags())
	return v, command
}

func configureViper(v *viper.Viper) {
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
}
