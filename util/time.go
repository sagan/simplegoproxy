package util

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A custom time format, that:
// When unmarshal from json, can be parsed from multiple time formats;
// When marshal into json, serialized to timestamp seconds number.
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
	return fmt.Sprintf("%q", time.Time(*ct).UTC().Format(formats[0]))
}
