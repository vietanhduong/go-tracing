package tracing

import "github.com/samber/lo"

type Option func(*Client)

func WithChunkSize(chunkSize int) Option {
	return func(o *Client) {
		if chunkSize >= 0 {
			o.chunkSize = chunkSize
		}
	}
}

func WithTargetPid(targetPid ...int32) Option {
	return func(o *Client) {
		o.targetPids = lo.Filter(targetPid, func(pid int32, _ int) bool {
			return pid > 0
		})
	}
}
