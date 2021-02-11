package utils

import (
	"time"
)

// GetCTime returns current milliseconds of the unix epoch
func GetCTime() int64 {
	return UnixMilli(time.Now())
}

// UnixMilli returns the unix epoch in milliseconds of the input time.
func UnixMilli(t time.Time) int64 {
	return t.Unix()*1e3 + int64(t.Nanosecond())/1e6
}
