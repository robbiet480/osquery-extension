package dot1x

// WLAN profile XML parsing for the Windows backend. This logic is pure Go
// (no syscalls), so it lives outside the //go:build windows file and is
// compiled, tested, and coverage-counted on every platform.

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// readCharData consumes tokens until the end of the element the decoder is
// currently positioned inside, returning the concatenated direct character
// data (text in nested child elements is ignored). It must be called
// immediately after reading a StartElement.
func readCharData(dec *xml.Decoder) (string, bool) {
	var sb strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
		case xml.CharData:
			if depth == 0 {
				sb.Write(t)
			}
		case xml.EndElement:
			if depth == 0 {
				return sb.String(), true
			}
			depth--
		}
	}
}

// readIntCharData is readCharData parsed as a base-10 int.
func readIntCharData(dec *xml.Decoder) (int, bool) {
	s, ok := readCharData(dec)
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return v, true
}

// firstElementText returns the character data of the first element whose local
// name matches local (namespace prefix / xmlns attributes are ignored).
func firstElementText(xmlStr, local string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == local {
			return readCharData(dec)
		}
	}
}

// eapMethodTypeFromXML returns the integer <Type> nested inside the
// occurrence-th <EapMethod> element (1 = outer EAP method, 2 = inner method
// used by tunneled auth such as PEAP/EAP-TTLS). Matching is by local element
// name, so namespace prefixes and attributes on the elements are tolerated.
// Returns -1 when the requested EapMethod or its Type is absent or malformed.
func eapMethodTypeFromXML(xmlStr string, occurrence int) int {
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	methodCount := 0
	depth := 0
	inTarget := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return -1
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "EapMethod" && !inTarget {
				methodCount++
				if methodCount == occurrence {
					inTarget = true
					depth = 1
				}
				continue
			}
			if inTarget {
				depth++
				if t.Name.Local == "Type" {
					if v, ok := readIntCharData(dec); ok {
						return v
					}
					return -1
				}
			}
		case xml.EndElement:
			if inTarget {
				depth--
				if depth == 0 {
					return -1 // left the target EapMethod without a Type
				}
			}
		}
	}
}

// extractEAPTypeFromXML parses the outer EAP method type from a WLAN profile
// XML (the <Type> inside the first <EapMethod>).
func extractEAPTypeFromXML(xmlStr string) int { return eapMethodTypeFromXML(xmlStr, 1) }

// extractInnerEAPTypeFromXML parses the inner EAP method type used by tunneled
// methods like PEAP (25) or EAP-TTLS (21): the <Type> inside the second
// <EapMethod>.
func extractInnerEAPTypeFromXML(xmlStr string) int { return eapMethodTypeFromXML(xmlStr, 2) }

// extractAuthModeFromXML parses <authMode> from the OneX section of a WLAN
// profile XML and maps it to an EAPOLControlMode value.
func extractAuthModeFromXML(xmlStr string) int {
	s, ok := firstElementText(xmlStr, "authMode")
	if !ok {
		return -1
	}
	switch strings.TrimSpace(s) {
	case "machine":
		return 3 // System
	case "user":
		return 1 // User
	case "machineOrUser":
		return 2 // LoginWindow
	case "guest":
		return 0 // None
	default:
		return -1
	}
}

// extractTrustedRootCAFromXML parses <TrustedRootCA> hex hashes from the
// ServerValidation section of a WLAN profile XML. These are the SHA-1
// fingerprints of the CA certificates configured for RADIUS server validation.
// All whitespace (spaces, newlines, tabs from pretty-printed XML) is stripped
// before the length check. Multiple hashes are comma-separated with
// colon-delimited hex pairs.
func extractTrustedRootCAFromXML(xmlStr string) string {
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	var hashes []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "TrustedRootCA" {
			text, ok := readCharData(dec)
			if !ok {
				continue
			}
			hex := strings.Join(strings.Fields(text), "")
			// A SHA-1 thumbprint is exactly 40 hex chars; require valid hex so
			// malformed profile content isn't emitted as a bogus fingerprint.
			if len(hex) == 40 && isHexString(hex) {
				hashes = append(hashes, formatSHA1Hex(hex))
			}
		}
	}
	return strings.Join(hashes, ",")
}

// isHexString reports whether s consists solely of hexadecimal digits.
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// formatSHA1Hex converts an even-length hex string to colon-separated pairs
// (e.g. "aabb..." -> "aa:bb:..."). Returns "" for odd-length input rather than
// panicking on the trailing 2-char slice.
func formatSHA1Hex(hex string) string {
	if len(hex)%2 != 0 {
		return ""
	}
	hex = strings.ToLower(hex)
	var buf strings.Builder
	buf.Grow(59)
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			buf.WriteByte(':')
		}
		buf.WriteString(hex[i : i+2])
	}
	return buf.String()
}
