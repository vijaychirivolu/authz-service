// Package logger provides structured logging capabilities for the application
package logger

import (
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	log  *logrus.Logger
	once sync.Once
)

// LogConfig holds logger configuration options
type LogConfig struct {
	Level  string // debug, info, warn, error, fatal, panic
	Format string // json, text
	Output io.Writer
}

// SetupLogrusFormatter configures the logrus formatter based on the format string
func setupLogrusFormatter(format string) logrus.Formatter {
	switch strings.ToLower(format) {
	case "text":
		return &logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		}
	default:
		return &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		}
	}
}

// ParseLogLevel parses a string log level to a logrus level
func parseLogLevel(level string) logrus.Level {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn", "warning":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	case "panic":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}

// InitLogger configures the logger for structured logging
func InitLogger(config LogConfig) {
	once.Do(func() {
		log = logrus.New()

		// Set formatter
		log.SetFormatter(setupLogrusFormatter(config.Format))

		// Set output
		if config.Output != nil {
			log.SetOutput(config.Output)
		} else {
			log.SetOutput(os.Stdout)
		}

		// Set level
		log.SetLevel(parseLogLevel(config.Level))

		// Add caller info to all log entries
		log.SetReportCaller(true)
	})
}

// getLogger ensures logger is initialized before use
func getLogger() *logrus.Logger {
	if log == nil {
		// Initialize with defaults if not already done
		InitLogger(LogConfig{
			Level:  "info",
			Format: "json",
			Output: os.Stdout,
		})
	}
	return log
}

// getCaller returns the caller information for logging
func getCaller(skip int) (string, string, int) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown", "unknown", 0
	}

	// Get just the function name
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown", file, line
	}

	// Get full function name
	funcName := fn.Name()

	// Extract only the function name without path
	parts := strings.Split(funcName, ".")
	funcName = parts[len(parts)-1]

	// For file, get only the base filename
	parts = strings.Split(file, "/")
	file = parts[len(parts)-1]

	return funcName, file, line
}

// generateCallStack generates a dynamic call stack
func generateCallStack(skip int, depth int) string {
	var builder strings.Builder

	for i := skip; i < skip+depth; i++ {
		fn, file, line := getCaller(i)
		if fn == "unknown" && file == "unknown" {
			break
		}
		builder.WriteString(file)
		builder.WriteString(":")
		builder.WriteString(fn)
		builder.WriteString(":")
		builder.WriteString(string(line))
		builder.WriteString("\n")
	}

	return builder.String()
}

// addCallerInfo adds caller information to the given fields
func addCallerInfo(fields logrus.Fields) logrus.Fields {
	fn, file, line := getCaller(3) // Skip through our logging functions

	if fields == nil {
		fields = logrus.Fields{}
	}

	fields["function"] = fn
	fields["file"] = file
	fields["line"] = line

	return fields
}

// LogRequest logs HTTP request details
func LogRequest(requestID, userID, ip string, statusCode int, duration time.Duration, errorMessage string) {
	fields := logrus.Fields{
		"request_id":  requestID,
		"user_id":     userID,
		"ip_address":  ip,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
	}

	if errorMessage != "" {
		fields["error"] = errorMessage
	}

	fields = addCallerInfo(fields)

	if statusCode >= 500 {
		getLogger().WithFields(fields).Error("Request error")
	} else if statusCode >= 400 {
		getLogger().WithFields(fields).Warn("Request warning")
	} else {
		getLogger().WithFields(fields).Info("Request processed")
	}
}

// LogInfo logs at INFO level
func LogInfo(message string, fields ...interface{}) {
	getLogger().WithFields(addCallerInfo(ParseFields(fields...))).Info(message)
}

// LogWarn logs at WARN level
func LogWarn(message string, fields ...interface{}) {
	getLogger().WithFields(addCallerInfo(ParseFields(fields...))).Warn(message)
}

// LogDebug logs at DEBUG level
func LogDebug(message string, fields ...interface{}) {
	getLogger().WithFields(addCallerInfo(ParseFields(fields...))).Debug(message)
}

// LogError logs at ERROR level
func LogError(message string, fields ...interface{}) {
	logFields := ParseFields(fields...)

	// Add call stack for errors
	logFields["call_stack"] = generateCallStack(3, 5)

	getLogger().WithFields(addCallerInfo(logFields)).Error(message)
}

// LogFatal logs at FATAL level
func LogFatal(message string, fields ...interface{}) {
	logFields := ParseFields(fields...)

	// Add call stack for fatal errors
	logFields["call_stack"] = generateCallStack(3, 10)

	getLogger().WithFields(addCallerInfo(logFields)).Fatal(message)
}

// LogPanic logs at PANIC level
func LogPanic(message string, fields ...interface{}) {
	logFields := ParseFields(fields...)

	// Add full call stack for panics
	logFields["call_stack"] = generateCallStack(3, 15)

	getLogger().WithFields(addCallerInfo(logFields)).Panic(message)
}

// ParseFields converts variadic fields into structured logging fields
func ParseFields(fields ...interface{}) logrus.Fields {
	logFields := logrus.Fields{}

	// Must have pairs of key/value
	if len(fields)%2 != 0 {
		return logFields
	}

	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue // Skip non-string keys
		}

		// Handle error values specially
		if err, isErr := fields[i+1].(error); isErr && err != nil {
			logFields[key] = err.Error()
		} else {
			logFields[key] = fields[i+1]
		}
	}

	return logFields
}
