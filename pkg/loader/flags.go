package loader

import (
	"flag"

	"github.com/spf13/viper"
)

const (
	namespace    = "loader"
	compilerFlag = namespace + ".compiler"
	libdirFlag   = namespace + ".library"
)

func RegisterFlags(fs *flag.FlagSet) {
	fs.String(compilerFlag, "clang", "The `binary` used to compile C to BPF.")
	fs.String(libdirFlag, "/var/lib/cooper/bpf", "The cooper's library directory which is contained BPF sources and headers.")
}

func InitFromViper(v *viper.Viper) *Loader {
	return New(v.GetString(libdirFlag), &Options{Compiler: v.GetString(compilerFlag)})
}
