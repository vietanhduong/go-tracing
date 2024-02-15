package tracing

type Option func(*Client)

func WithChunkSize(chunkSize int) Option {
	return func(o *Client) {
		if chunkSize >= 0 {
			o.chunkSize = chunkSize
		}
	}
}
