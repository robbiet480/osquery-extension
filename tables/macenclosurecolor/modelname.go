package macenclosurecolor

import "encoding/json"

// parseModelName extracts the human-readable Model Name from the JSON output of
// `system_profiler SPHardwareDataType -json`. Returns "" if the JSON is
// malformed, empty, or missing the expected field. Split out as a pure function
// over bytes so it can be unit-tested without invoking system_profiler.
func parseModelName(systemProfilerJSON []byte) string {
	var parsed struct {
		SPHardwareDataType []struct {
			MachineName string `json:"machine_name"`
		} `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal(systemProfilerJSON, &parsed); err != nil {
		return ""
	}
	if len(parsed.SPHardwareDataType) == 0 {
		return ""
	}
	return parsed.SPHardwareDataType[0].MachineName
}
