//go:build windows

package dot1x

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wlanClientVersion = 2

	wlanIntfOpcodeCurrentConnection uint32 = 7

	wlanIfaceStateNotReady       uint32 = 0
	wlanIfaceStateConnected      uint32 = 1
	wlanIfaceStateAdHocFormed    uint32 = 2
	wlanIfaceStateDisconnecting  uint32 = 3
	wlanIfaceStateDisconnected   uint32 = 4
	wlanIfaceStateAssociating    uint32 = 5
	wlanIfaceStateDiscovering    uint32 = 6
	wlanIfaceStateAuthenticating uint32 = 7
)

type windowsGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g windowsGUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

type wlanInterfaceInfo struct {
	InterfaceGuid           windowsGUID
	StrInterfaceDescription [256]uint16
	IsState                 uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

type dot11SSID struct {
	SSIDLength uint32
	SSID       [32]byte
}

type wlanAssociationAttributes struct {
	Dot11Ssid         dot11SSID
	Dot11BssType      uint32
	Dot11Bssid        [6]byte
	_                 [2]byte // align to 4-byte boundary
	Dot11PhyType      uint32
	Dot11PhyIndex     uint32
	WlanSignalQuality uint32
	RxRate            uint32
	TxRate            uint32
}

type wlanSecurityAttributes struct {
	SecurityEnabled int32
	OneXEnabled     int32
	AuthAlgorithm   uint32
	CipherAlgorithm uint32
}

type wlanConnectionAttributes struct {
	IsState               uint32
	ConnectionMode        uint32
	ProfileName           [256]uint16
	AssociationAttributes wlanAssociationAttributes
	SecurityAttributes    wlanSecurityAttributes
}

var (
	modWlanapi = syscall.NewLazyDLL("wlanapi.dll")

	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetProfile     = modWlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	wlanOnce sync.Once
	// wlanAvail reports whether wlanapi.dll loaded and a client handle opened.
	wlanAvail bool
	// wlanHandle is a process-lifetime WLAN client handle opened once in
	// initWlan and reused by every query. Like the darwin framework handle, it
	// is intentionally never closed — the OS reclaims it at process exit, and
	// reusing one handle avoids an open/close round-trip on every GetStatus.
	wlanHandle uintptr
)

func initWlan() {
	if err := modWlanapi.Load(); err != nil {
		return
	}
	for _, p := range []*syscall.LazyProc{
		procWlanOpenHandle, procWlanEnumInterfaces,
		procWlanQueryInterface, procWlanGetProfile, procWlanFreeMemory,
	} {
		if err := p.Find(); err != nil {
			return
		}
	}
	h, err := openWlanHandle()
	if err != nil {
		return
	}
	wlanHandle = h
	wlanAvail = true
}

// ifaceInfo is the per-interface data captured from a single
// WlanEnumInterfaces call: its GUID (stable) and current state.
type ifaceInfo struct {
	guid  windowsGUID
	state uint32
}

// windowsBackend reuses the process-lifetime WLAN handle and, on first use,
// snapshots all interfaces into ifaces so that querying several interfaces in
// one table generation enumerates only once instead of once per interface.
type windowsBackend struct {
	handle  uintptr
	once    sync.Once
	ifaces  map[string]ifaceInfo
	enumErr error
}

func newBackend() Dot1XBackend {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return unavailableBackend{}
	}
	return &windowsBackend{handle: wlanHandle}
}

type unavailableBackend struct{}

func (unavailableBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	return Dot1XStatus{Interface: ifname},
		fmt.Errorf("%w: wlanapi.dll not available on this system", ErrBackendUnavailable)
}

func openWlanHandle() (uintptr, error) {
	var negotiatedVersion uint32
	var handle uintptr
	ret, _, _ := procWlanOpenHandle.Call(
		uintptr(wlanClientVersion),
		0,
		uintptr(unsafe.Pointer(&negotiatedVersion)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("WlanOpenHandle failed: %w", syscall.Errno(ret))
	}
	return handle, nil
}

func freeWlanMemory(p uintptr) {
	procWlanFreeMemory.Call(p) //nolint:errcheck
}

// enumerateWlanInterfaceInfos performs one WlanEnumInterfaces call and returns
// a description->info map plus the descriptions in enumeration order.
func enumerateWlanInterfaceInfos(handle uintptr) (map[string]ifaceInfo, []string, error) {
	var listPtr unsafe.Pointer
	ret, _, _ := procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if ret != 0 || listPtr == nil {
		return nil, nil, fmt.Errorf("WlanEnumInterfaces failed: %w", syscall.Errno(ret))
	}
	defer freeWlanMemory(uintptr(listPtr))

	list := (*wlanInterfaceInfoList)(listPtr)
	infos := make(map[string]ifaceInfo, list.NumberOfItems)
	names := make([]string, 0, list.NumberOfItems)

	headerSize := unsafe.Sizeof(*list)
	itemSize := unsafe.Sizeof(wlanInterfaceInfo{})
	for i := uint32(0); i < list.NumberOfItems; i++ {
		offset := headerSize + uintptr(i)*itemSize
		info := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(list)) + offset))
		desc := utf16ToString(info.StrInterfaceDescription[:])
		if _, dup := infos[desc]; !dup {
			names = append(names, desc)
		}
		infos[desc] = ifaceInfo{guid: info.InterfaceGuid, state: info.IsState}
	}
	return infos, names, nil
}

// enumerateWlanInterfaces returns the descriptions of all wireless interfaces.
func enumerateWlanInterfaces() []string {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return nil
	}
	_, names, err := enumerateWlanInterfaceInfos(wlanHandle)
	if err != nil {
		return nil
	}
	return names
}

func defaultInterfaces() []string {
	ifaces := enumerateWlanInterfaces()
	if len(ifaces) == 0 {
		return nil
	}
	return ifaces
}

// snapshot lazily enumerates interfaces once per backend instance (i.e. once
// per table generation) and caches the result.
func (b *windowsBackend) snapshot() (map[string]ifaceInfo, error) {
	b.once.Do(func() {
		b.ifaces, _, b.enumErr = enumerateWlanInterfaceInfos(b.handle)
	})
	return b.ifaces, b.enumErr
}

func (b *windowsBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	infos, err := b.snapshot()
	if err != nil {
		// Enumeration failing is systemic (affects every interface), so report
		// it as backend-unavailable rather than a per-interface miss.
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
	}
	info, ok := infos[ifname]
	if !ok {
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("wireless interface %q not found", ifname)
	}
	guid := info.guid
	ifState := info.state

	s := Dot1XStatus{
		Interface:        ifname,
		UniqueIdentifier: guid.String(),
	}

	s.State, s.SupplicantState = mapWlanState(ifState)
	s.ClientStatus = -1
	s.DomainSpecificError = -1
	s.Mode = -1
	s.TLSTrustClientStatus = -1
	s.TLSNegotiatedCipher = -1
	s.InnerEAPType = -1
	s.EAPType = -1

	if ifState != wlanIfaceStateConnected && ifState != wlanIfaceStateAuthenticating {
		return s, nil
	}

	var dataSize uint32
	var dataPtr unsafe.Pointer
	var opcodeValueType uint32
	ret, _, _ := procWlanQueryInterface.Call(
		b.handle,
		uintptr(unsafe.Pointer(&guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		uintptr(unsafe.Pointer(&opcodeValueType)),
	)
	if ret != 0 {
		// The interface reports connected/authenticating, so a failed
		// current-connection query would leave a misleading "successful" row
		// missing MAC/EAP/profile data. Return a per-interface error so
		// generateRows skips it rather than emitting a partial row.
		return s, fmt.Errorf("WlanQueryInterface(current_connection) failed for %q: %w", ifname, syscall.Errno(ret))
	}
	if dataPtr == nil {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) returned no data for %q", ifname)
	}
	defer freeWlanMemory(uintptr(dataPtr))

	conn := (*wlanConnectionAttributes)(dataPtr)

	s.AuthenticatorMACAddress = macAddrString(conn.AssociationAttributes.Dot11Bssid[:])

	sec := conn.SecurityAttributes
	if sec.OneXEnabled != 0 {
		if ifState == wlanIfaceStateConnected {
			s.SupplicantState = 4 // Authenticated
			s.ClientStatus = 0
		}
	} else {
		s.SupplicantState = 0 // not an 802.1X network
	}

	profileName := utf16ToString(conn.ProfileName[:])
	if profileName != "" {
		if xmlStr, err := getWlanProfileXML(b.handle, &guid, profileName); err == nil {
			if eapType := extractEAPTypeFromXML(xmlStr); eapType > 0 {
				s.EAPType = eapType
			}
			if mode := extractAuthModeFromXML(xmlStr); mode >= 0 {
				s.Mode = mode
			}
			if innerType := extractInnerEAPTypeFromXML(xmlStr); innerType > 0 {
				s.InnerEAPType = innerType
			}
			if sha1 := extractTrustedRootCAFromXML(xmlStr); sha1 != "" {
				s.TLSServerCertificateSHA1 = sha1
			}
		}
	}

	return s, nil
}

// getWlanProfileXML calls WlanGetProfile and returns the profile XML string.
func getWlanProfileXML(handle uintptr, guid *windowsGUID, profileName string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(profileName)
	if err != nil {
		return "", err
	}
	var xmlPtr *uint16
	var flags uint32
	ret, _, _ := procWlanGetProfile.Call(
		handle,
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&xmlPtr)),
		uintptr(unsafe.Pointer(&flags)),
		0,
	)
	if ret != 0 || xmlPtr == nil {
		return "", fmt.Errorf("WlanGetProfile failed: %w", syscall.Errno(ret))
	}
	defer freeWlanMemory(uintptr(unsafe.Pointer(xmlPtr)))
	return utf16PtrToString(xmlPtr), nil
}

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
			if len(hex) == 40 {
				hashes = append(hashes, formatSHA1Hex(hex))
			}
		}
	}
	return strings.Join(hashes, ",")
}

// formatSHA1Hex converts a 40-char hex string to colon-separated pairs
// (e.g. "aabb..." -> "aa:bb:...").
func formatSHA1Hex(hex string) string {
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

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// mapWlanState maps WLAN_INTERFACE_STATE to (EAPOLControlState, SupplicantState).
func mapWlanState(state uint32) (int, int) {
	switch state {
	case wlanIfaceStateConnected:
		return 2, 4 // Running, Authenticated
	case wlanIfaceStateAuthenticating:
		return 2, 3 // Running, Authenticating
	case wlanIfaceStateAssociating:
		return 1, 1 // Starting, Connecting
	case wlanIfaceStateDiscovering:
		return 1, 2 // Starting, Acquired
	case wlanIfaceStateDisconnecting:
		return 3, 6 // Stopping, Logoff
	case wlanIfaceStateDisconnected:
		return 0, 0 // Idle, Disconnected
	case wlanIfaceStateNotReady:
		return 0, 7 // Idle, Inactive
	default:
		return 0, 0
	}
}

func utf16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			return syscall.UTF16ToString(s[:i])
		}
	}
	return syscall.UTF16ToString(s)
}
