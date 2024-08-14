package util

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A custom time format, that:
// When Mar
type TimestampTime time.Time

var formats = []string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05-07:00"}

func (ct *TimestampTime) UnmarshalJSON(b []byte) (err error) {
	s := strings.Trim(string(b), `"`)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		*ct = TimestampTime(time.Unix(i, 0))
		return nil
	}
	for _, format := range formats {
		if nt, err := time.Parse(format, s); err == nil {
			*ct = TimestampTime(nt)
			return nil
		}
	}
	return fmt.Errorf("invalid time")
}

func (ct TimestampTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprint(time.Time(ct).Unix())), nil
}

func (ct *TimestampTime) String() string {
	t := time.Time(*ct)
	return fmt.Sprintf("%q", t.Format(formats[0]))
}

func (ct *TimestampTime) Format(layout string) string {
	t := time.Time(*ct)
	return fmt.Sprintf("%q", t.Format(layout))
}
