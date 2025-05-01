package logger

import (
	"runtime"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	log  *logrus.Logger
	once sync.Once
)

// LogEntry represents the structure of a log entry.
type LogEntry struct {
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	UserID     string `json:"user_id"`
	IP         string `json:"ip_address"`
	StatusCode int    `json:"status_code"`
	Duration   int64  `json:"duration"`
	Error      string `json:"error"`
}

// InitLogger configures the logger for structured JSON logging.
// It's safe to call multiple times - will only initialize once.
func InitLogger() {
	once.Do(func() {
		log = logrus.New()
		log.SetFormatter(&logrus.JSONFormatter{})
		log.SetLevel(logrus.InfoLevel)
	})
}

// getLogger ensures logger is initialized before use
func getLogger() *logrus.Logger {
	if log == nil {
		InitLogger()
	}
	return log
}

// GenerateStackTrace generates a dynamic stack trace
func GenerateStackTrace() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// logMessage is a generic function to log messages at different levels.
func logMessage(level logrus.Level, message string, logFields logrus.Fields) {
	if level == logrus.ErrorLevel || level == logrus.FatalLevel || level == logrus.PanicLevel {
		//logFields["error"] = errorMessage
		logFields["stack_trace"] = GenerateStackTrace()
	}
	getLogger().WithFields(logFields).Log(level, message)
}

// LogRequest logs the HTTP request details at INFO level.
func LogRequest(requestID, userID, ip string, statusCode int, duration int64, errorMessage string) {
	logEntry := LogEntry{
		Message:    "Request processed",
		RequestID:  requestID,
		UserID:     userID,
		IP:         ip,
		StatusCode: statusCode,
		Duration:   duration,
		Error:      errorMessage,
	}

	logMessage(logrus.TraceLevel, logEntry.Message, logrus.Fields{
		"request_id":  logEntry.RequestID,
		"user_id":     logEntry.UserID,
		"ip_address":  logEntry.IP,
		"status_code": logEntry.StatusCode,
		"duration":    logEntry.Duration,
		"error":       logEntry.Error,
	})
}

// LogInfo logs general info messages at INFO level.
func LogInfo(message string, fields ...interface{}) {
	getLogger().WithFields(ParseFields(fields...)).Info(message)
}

// LogWarn logs warnings at WARN level.
func LogWarn(message string, fields ...interface{}) {
	getLogger().WithFields(ParseFields(fields...)).Warn(message)
}

// LogDebug logs debug messages at DEBUG level.
func LogDebug(message string, fields ...interface{}) {
	getLogger().WithFields(ParseFields(fields...)).Debug(message)
}

// LogFatal logs fatal messages at FATAL level.
func LogFatal(message string, fields ...interface{}) {
	getLogger().WithFields(ParseFields(fields...)).Error(message) // Changed from Fatal to Error for testing
}

// LogError logs error messages at ERROR level.
func LogError(message string, fields ...interface{}) {
	getLogger().WithFields(ParseFields(fields...)).Error(message)
}

// LogPanic logs error messages at PANIC level.
func LogPanic(message string, fields ...interface{}) {
	logMessage(logrus.PanicLevel, message, ParseFields(fields...))
}

// Helper func to convert variadic fields into structured logging fields
func ParseFields(fields ...interface{}) logrus.Fields {
	logFields := logrus.Fields{}

	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue // skip the non-string keys
		}

		// if the field is an error, log its error message
		if err, isErr := fields[i+1].(error); isErr {
			logFields[key] = err.Error()
		} else {
			logFields[key] = fields[i+1]
		}
	}

	return logFields
}
