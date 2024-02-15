package loader

import (
	"context"
	"fmt"
	"path"

	"github.com/vietanhduong/wbpf/compiler"
)

// var log = logging.DefaultLogger.WithFields(logrus.Fields{logfields.LogSubsys: "loader"})

type Interface interface {
	Compile(ctx context.Context, source string, cflags ...string) (string, error)
}

type Options struct {
	Compiler string
}

type Loader struct {
	libdir string
	opts   *Options
}

var _ Interface = (*Loader)(nil)

func New(libdir string, opts *Options) *Loader {
	if opts == nil {
		opts = &Options{}
	}
	return &Loader{libdir: libdir, opts: opts}
}

// Compile the input source to BPF object. The input source is the program source (base) filename
// to be compiled, and must be presented in the libdir.
// The cflags arguments can be used to pass variable definations.
//
// For examples: -DCFG_MAX_RINGBUF_ENTRIES=1000 -DCFG_PROBE_NAME="kprobe_execve"
func (l *Loader) Compile(ctx context.Context, source string, cflags ...string) (string, error) {
	// build includes
	includes := []string{
		l.libdir,
		path.Join(l.libdir, "include"),
	}

	output, err := compiler.Compile(ctx, path.Join(l.libdir, source),
		compiler.WithCompiler(l.opts.Compiler),
		compiler.WithInclude(includes...),
		compiler.WithOutputDir(l.libdir),
		compiler.WithCFlags(cflags...),
	)
	if err != nil {
		return "", fmt.Errorf("compiler: %w", err)
	}
	return output, nil
}
