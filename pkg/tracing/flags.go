package tracing

import (
	"flag"

	"github.com/spf13/viper"
)

const (
	chungSizeFlag = "chunk-size"
)

func RegisterFlags(fs *flag.FlagSet) {
	fs.Int(chungSizeFlag, 84, "The message chunk size, this flag might impact when reading data from socket.")
}

func InitWithViper(args Args, v *viper.Viper) *Client {
	var opts []Option
	opts = append(opts, WithChunkSize(v.GetInt(chungSizeFlag)))
	return NewClient(args, opts...)
}
