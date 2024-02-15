package logging

import (
	"os"

	"github.com/sirupsen/logrus"
)

const (
	Syslog = "syslog"
)

var DefaultLogger = initDefaultLogger()

func initDefaultLogger() *logrus.Logger {
	opts := defaultLogOpts()
	logger := logrus.New()
	logger.SetLevel(opts.level)
	logger.SetReportCaller(true)
	logger.SetFormatter(opts.format.LogrusFormat())
	return logger
}

func WithFields(kv ...interface{}) *logrus.Entry {
	if len(kv)%2 == 1 {
		panic("invalid number of arguments")
	}
	fields := make(logrus.Fields)
	for i := 0; i < len(kv); i += 2 {
		fields[kv[i].(string)] = kv[i+1]
	}
	return DefaultLogger.WithFields(fields)
}

// SetLogLevel updates the DefaultLogger with a new logrus.Level
func SetLogLevel(logLevel logrus.Level) {
	DefaultLogger.SetLevel(logLevel)
}

// SetLogLevelToDebug updates the DefaultLogger with the logrus.DebugLevel
func SetLogLevelToDebug() {
	DefaultLogger.SetLevel(logrus.DebugLevel)
}

// SetLogFormat updates the DefaultLogger with a new LogFormat
func SetLogFormat(format LogFormat) {
	DefaultLogger.SetFormatter(format.LogrusFormat())
}

// AddHooks adds additional logrus hook to default logger
func AddHooks(hooks ...logrus.Hook) {
	for _, hook := range hooks {
		DefaultLogger.AddHook(hook)
	}
}

// SetupLogging used to setup DefaultLogger based on the input log options.
func SetupLogging(logOpts ...LogOption) {
	opts := defaultLogOpts()
	for _, opt := range logOpts {
		opt(opts)
	}

	// Updating the default log format
	SetLogFormat(opts.format)
	logrus.SetOutput(os.Stdout)
	SetLogLevel(opts.level)

	// always suppress the default logger so libraries don't print things
	logrus.SetLevel(logrus.PanicLevel)
}
