package tracing

import (
	"flag"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/viper"
)

const (
	chungSizeFlag  = "chunk-size"
	targetPidsFlag = "target-pids"
)

func RegisterFlags(fs *flag.FlagSet) {
	fs.Int(chungSizeFlag, 84, "The message chunk size, this flag might impact when reading data from socket.")
	fs.String(targetPidsFlag, "", "The target pids to trace. Separate by comma.")
}

func InitWithViper(args Args, v *viper.Viper) *Client {
	var opts []Option
	opts = append(opts, WithChunkSize(v.GetInt(chungSizeFlag)))
	opts = append(opts, WithTargetPid(lo.Map(strings.Split(v.GetString(targetPidsFlag), ","), func(s string, _ int) int32 {
		val, _ := strconv.ParseInt(s, 10, 32)
		return int32(val)
	})...))
	return NewClient(args, opts...)
}
