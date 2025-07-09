package xtime

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ParseDuration parses a duration string.
// examples: "10d", "-1.5w" or "3Y4M5d".
// Add time units are "d"="D", "w"="W", "M", "y"="Y".
// Source: https://gist.github.com/xhit/79c9e137e1cfe332076cdda9f5e24699?permalink_comment_id=5170854#gistcomment-5170854
func ParseDuration(s string) (time.Duration, error) {
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}

	re := regexp.MustCompile(`(\d*\.\d+|\d+)[^\d]*`)
	unitMap := map[string]time.Duration{
		"d": 24,
		"D": 24,
		"w": 7 * 24,
		"W": 7 * 24,
		"M": 30 * 24,
		"y": 365 * 24,
		"Y": 365 * 24,
	}

	strs := re.FindAllString(s, -1)
	var sumDur time.Duration
	for _, str := range strs {
		var _hours time.Duration = 1
		for unit, hours := range unitMap {
			if strings.Contains(str, unit) {
				str = strings.ReplaceAll(str, unit, "h")
				_hours = hours
				break
			}
		}

		dur, err := time.ParseDuration(str)
		if err != nil {
			return 0, err
		}

		sumDur += dur * _hours
	}

	if neg {
		sumDur = -sumDur
	}

	return sumDur, nil
}

// FormatDuration formats a duration into a string with friendly units.
// Returns strings like "10d", "-1w2d", "3Y4M5d", etc.
// Uses the same units as ParseDuration: "d", "w", "M", "Y".
// The round parameter specifies the smallest unit to include.
func FormatDuration(d time.Duration, round time.Duration) string {
	if d == 0 {
		return "0d"
	}

	// Round the duration to the specified precision
	if round > 0 {
		d = d.Round(round)
		if d == 0 {
			return "0d"
		}
	}

	neg := d < 0
	if neg {
		d = -d
	}

	hours := int64(d / time.Hour)

	// Convert to largest units first
	years := hours / (365 * 24)
	hours %= (365 * 24)

	months := hours / (30 * 24)
	hours %= (30 * 24)

	weeks := hours / (7 * 24)
	hours %= (7 * 24)

	days := hours / 24
	hours %= 24

	// Handle remaining time units
	remainder := d % time.Hour
	minutes := remainder / time.Minute
	remainder %= time.Minute
	seconds := remainder / time.Second
	remainder %= time.Second

	var parts []string

	if years > 0 {
		parts = append(parts, fmt.Sprintf("%dY", years))
	}
	if months > 0 {
		parts = append(parts, fmt.Sprintf("%dM", months))
	}
	if weeks > 0 {
		parts = append(parts, fmt.Sprintf("%dw", weeks))
	}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 && round <= time.Hour {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 && round <= time.Minute {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 && round <= time.Second {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if remainder > 0 && round < time.Second {
		if remainder%time.Millisecond == 0 && round <= time.Millisecond {
			parts = append(parts, fmt.Sprintf("%dms", remainder/time.Millisecond))
		} else if remainder%time.Microsecond == 0 && round <= time.Microsecond {
			parts = append(parts, fmt.Sprintf("%dµs", remainder/time.Microsecond))
		} else if round <= time.Nanosecond {
			parts = append(parts, fmt.Sprintf("%dns", remainder/time.Nanosecond))
		}
	}

	// If no parts were added (shouldn't happen with the zero check above)
	if len(parts) == 0 {
		parts = append(parts, "0d")
	}

	result := strings.Join(parts, "")
	if neg {
		result = "-" + result
	}

	return result
}
