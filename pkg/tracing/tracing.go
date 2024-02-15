package tracing

import (
	"context"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vietanhduong/go-tracing/pkg/loader"
	"github.com/vietanhduong/go-tracing/pkg/logging"
	"github.com/vietanhduong/go-tracing/pkg/logging/logfields"
	"github.com/vietanhduong/go-tracing/pkg/utils"
	"github.com/vietanhduong/wbpf"
)

var log = logging.WithFields(logfields.LogSubsys, "tracing")

type Args struct {
	Loader loader.Interface
}

type Client struct {
	loader loader.Interface
	mod    *wbpf.Module

	// options
	chunkSize int // default 84
}

func NewClient(args Args, opt ...Option) *Client {
	this := &Client{
		loader: args.Loader,
	}
	for _, o := range opt {
		o(this)
	}
	return this
}

func (c *Client) Init(ctx context.Context) error {
	if c.mod != nil {
		return nil
	}

	if utils.IsNil(c.loader) {
		return fmt.Errorf("loader is nil")
	}

	objectPath, err := c.loader.Compile(ctx, "socket_trace.bpf.c",
		"-DCFG_RINGBUF_SIZE=16777216",
		fmt.Sprintf("-DCFG_CHUNK_SIZE=%d", c.chunkSize),
	)
	if err != nil {
		return fmt.Errorf("failed to compile: %w", err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to acquire memory lock: %w", err)
	}

	c.mod, err = wbpf.NewModule(wbpf.WithElfFile(objectPath))
	if err != nil {
		return fmt.Errorf("failed to new module: %w", err)
	}

	if err = c.mod.AttachFExit("sys_accept4"); err != nil {
		return fmt.Errorf("failed to attach sys_accept4: %w", err)
	}

	if err = c.mod.AttachFExit("sys_recvfrom"); err != nil {
		return fmt.Errorf("failed to attach sys_recvfrom: %w", err)
	}

	sysclose := wbpf.FixSyscallName("sys_close")
	if err = c.mod.AttachKprobe(sysclose, "entry_close"); err != nil {
		return fmt.Errorf("failed to attach sys_close: %w", err)
	}

	if err = c.mod.AttachKretprobe(sysclose, "ret_close"); err != nil {
		return fmt.Errorf("failed to attach sys_close: %w", err)
	}

	if err = c.mod.OpenRingBuffer("socket_events", nil); err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	runtime.SetFinalizer(c, func(c *Client) { c.Close() })
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	defer c.Close()
	if err := c.runSocketEventHandler(ctx); err != nil {
		return fmt.Errorf("failed to run socket event handler: %w", err)
	}
	<-ctx.Done()
	return nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	if c.mod != nil {
		c.mod.Close()
	}
	return nil
}
