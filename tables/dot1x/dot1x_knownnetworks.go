package dot1x

import (
	"net"
	"strings"
	"time"

	"github.com/micromdm/plist"
)

// knownNetworkSSID returns the SSID of the known network that was associated
// on bssid, the AP the 802.1X session authenticated against. Several networks
// can share a BSSID (one radio, multiple SSIDs); the most recent association
// wins. Only SSID/BSSID/LastAssociatedAt are read; the plist also holds AP
// locations, which are deliberately ignored. Returns "" if nothing matches or
// the plist can't be parsed.
func knownNetworkSSID(plistData []byte, bssid string) string {
	want, err := net.ParseMAC(padMAC(bssid))
	if err != nil || len(plistData) == 0 {
		return ""
	}
	// Decode loosely: the file also holds non-network keys of other types,
	// which would make a typed map fail as a whole.
	var top map[string]any
	if plist.Unmarshal(plistData, &top) != nil {
		return ""
	}
	var best string
	var bestAt time.Time
	for key, v := range top {
		n, ok := v.(map[string]any)
		if !strings.HasPrefix(key, "wifi.network.ssid.") || !ok {
			continue
		}
		ssid, _ := n["SSID"].([]byte)
		list, _ := n["BSSList"].([]any)
		for _, e := range list {
			b, _ := e.(map[string]any)
			bssid, _ := b["BSSID"].(string)
			at, _ := b["LastAssociatedAt"].(time.Time)
			if mac, err := net.ParseMAC(padMAC(bssid)); err == nil && len(ssid) > 0 &&
				mac.String() == want.String() && (best == "" || at.After(bestAt)) {
				best, bestAt = string(ssid), at
			}
		}
	}
	return best
}

// padMAC zero-pads each octet of a colon MAC ("2a:b:8b:0:f2:35" ->
// "2a:0b:8b:00:f2:35"), the form macOS uses in the known-networks plist.
func padMAC(s string) string {
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// profileSSID returns the SSID bound to an EAPOLClientProfile in eap8021x's
// client configuration (Profiles -> <ProfileID> -> WLAN -> SSID). A
// profile-based session (typically MDM-deployed) reports that ProfileID as
// its UniqueIdentifier, so this identifies the network exactly. Returns ""
// for unknown profiles, profiles without a WLAN binding, or bad input.
func profileSSID(plistData []byte, profileID string) string {
	if profileID == "" || len(plistData) == 0 {
		return ""
	}
	var cfg map[string]any
	if plist.Unmarshal(plistData, &cfg) != nil {
		return ""
	}
	profiles, _ := cfg["Profiles"].(map[string]any)
	profile, _ := profiles[profileID].(map[string]any)
	wlan, _ := profile["WLAN"].(map[string]any)
	switch ssid := wlan["SSID"].(type) {
	case []byte:
		return string(ssid)
	case string:
		return ssid
	}
	return ""
}
