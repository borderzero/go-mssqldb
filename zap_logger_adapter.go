package mssql

import (
	"context"

	"github.com/microsoft/go-mssqldb/msdsn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// msdnsLogToZapLog is a map of msdns log levels to zap log levels.
var msdnsLogToZapLog = map[msdsn.Log]zapcore.Level{
	msdsn.LogDebug:    zapcore.DebugLevel,
	msdsn.LogMessages: zapcore.InfoLevel,
	msdsn.LogErrors:   zapcore.ErrorLevel,
}

// zapContextLogger implements ContextLogger by wrapping a zap.Logger.
type zapContextLogger struct {
	logger *zap.Logger
}

// zapLoggerToContextLogger wraps a zap.Logger object as a ContextLogger interface implementation.
func zapLoggerToContextLogger(logger *zap.Logger) ContextLogger {
	return &zapContextLogger{logger: logger}
}

// Log emits a log with the given msdns log level.
func (l *zapContextLogger) Log(_ context.Context, level msdsn.Log, data string) {
	zapLevel, ok := msdnsLogToZapLog[level]
	if !ok {
		zapLevel = zapcore.InfoLevel
	}
	l.logger.Log(zapLevel, data)
}
