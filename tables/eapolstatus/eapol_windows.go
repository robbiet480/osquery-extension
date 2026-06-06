//go:build windows

package eapolstatus

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	wlanClientVersion = 2

	wlanIntfOpcodeCurrentConnection uint32 = 7

	wlanIfaceStateNotReady         uint32 = 0
	wlanIfaceStateConnected        uint32 = 1
	wlanIfaceStateAdHocFormed      uint32 = 2
	wlanIfaceStateDisconnecting    uint32 = 3
	wlanIfaceStateDisconnected     uint32 = 4
	wlanIfaceStateAssociating      uint32 = 5
	wlanIfaceStateDiscovering      uint32 = 6
	wlanIfaceStateAuthenticating   uint32 = 7
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
	SecurityEnabled  int32
	OneXEnabled      int32
	AuthAlgorithm    uint32
	CipherAlgorithm  uint32
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
	procWlanCloseHandle    = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetProfile     = modWlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	wlanOnce  sync.Once
	wlanAvail bool
)

func initWlan() {
	if err := modWlanapi.Load(); err != nil {
		return
	}
	for _, p := range []*syscall.LazyProc{
		procWlanOpenHandle, procWlanCloseHandle,
		procWlanEnumInterfaces, procWlanQueryInterface,
		procWlanGetProfile, procWlanFreeMemory,
	} {
		if err := p.Find(); err != nil {
			return
		}
	}
	wlanAvail = true
}

type windowsBackend struct{}

func newBackend() EAPOLBackend {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return unavailableBackend{}
	}
	return windowsBackend{}
}

type unavailableBackend struct{}

func (unavailableBackend) GetStatus(ifname string) (EAPOLStatus, error) {
	return EAPOLStatus{Interface: ifname},
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
		return 0, fmt.Errorf("WlanOpenHandle failed: %d", ret)
	}
	return handle, nil
}

func closeWlanHandle(handle uintptr) {
	procWlanCloseHandle.Call(handle, 0) //nolint:errcheck
}

func freeWlanMemory(p uintptr) {
	procWlanFreeMemory.Call(p) //nolint:errcheck
}

// enumerateWlanInterfaces returns the descriptions of all wireless interfaces.
func enumerateWlanInterfaces() []string {
	handle, err := openWlanHandle()
	if err != nil {
		return nil
	}
	defer closeWlanHandle(handle)

	var listPtr unsafe.Pointer
	ret, _, _ := procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if ret != 0 || listPtr == nil {
		return nil
	}
	defer freeWlanMemory(uintptr(listPtr))

	list := (*wlanInterfaceInfoList)(listPtr)
	if list.NumberOfItems == 0 {
		return nil
	}

	headerSize := unsafe.Sizeof(*list)
	itemSize := unsafe.Sizeof(wlanInterfaceInfo{})
	names := make([]string, 0, list.NumberOfItems)
	for i := uint32(0); i < list.NumberOfItems; i++ {
		offset := headerSize + uintptr(i)*itemSize
		info := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(list)) + offset))
		names = append(names, utf16ToString(info.StrInterfaceDescription[:]))
	}
	return names
}

func defaultInterfaces() []string {
	if !wlanAvail {
		return nil
	}
	ifaces := enumerateWlanInterfaces()
	if len(ifaces) == 0 {
		return nil
	}
	return ifaces
}

func (windowsBackend) GetStatus(ifname string) (EAPOLStatus, error) {
	handle, err := openWlanHandle()
	if err != nil {
		return EAPOLStatus{Interface: ifname},
			fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
	}
	defer closeWlanHandle(handle)

	guid, ifState, err := findWlanInterface(handle, ifname)
	if err != nil {
		return EAPOLStatus{Interface: ifname}, err
	}

	s := EAPOLStatus{
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
	ret, _, _ := procWlanQueryInterface.Call(
		handle,
		uintptr(unsafe.Pointer(guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		0,
	)
	if ret != 0 || dataPtr == nil {
		return s, nil
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
	}

	profileName := utf16ToString(conn.ProfileName[:])
	if profileName != "" {
		if xml, err := getWlanProfileXML(handle, guid, profileName); err == nil {
			if eapType := extractEAPTypeFromXML(xml); eapType > 0 {
				s.EAPType = eapType
			}
			if mode := extractAuthModeFromXML(xml); mode >= 0 {
				s.Mode = mode
			}
			if innerType := extractInnerEAPTypeFromXML(xml); innerType > 0 {
				s.InnerEAPType = innerType
			}
			if sha1 := extractTrustedRootCAFromXML(xml); sha1 != "" {
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
		return "", fmt.Errorf("WlanGetProfile failed: %d", ret)
	}
	defer freeWlanMemory(uintptr(unsafe.Pointer(xmlPtr)))
	return utf16PtrToString(xmlPtr), nil
}

// extractEAPTypeFromXML parses the EAP method type from a WLAN profile XML.
// The EAP type lives at EapMethod > Type inside the EAPConfig section.
func extractEAPTypeFromXML(xml string) int {
	methodIdx := strings.Index(xml, "<EapMethod>")
	if methodIdx < 0 {
		return -1
	}
	sub := xml[methodIdx:]
	typeStart := strings.Index(sub, "<Type")
	if typeStart < 0 {
		return -1
	}
	sub = sub[typeStart:]
	gt := strings.IndexByte(sub, '>')
	if gt < 0 {
		return -1
	}
	sub = sub[gt+1:]
	lt := strings.IndexByte(sub, '<')
	if lt < 0 {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(sub[:lt]))
	if err != nil {
		return -1
	}
	return v
}

// extractAuthModeFromXML parses <authMode> from the OneX section of a WLAN
// profile XML and maps it to an EAPOLControlMode value.
func extractAuthModeFromXML(xml string) int {
	const open = "<authMode>"
	const close = "</authMode>"
	start := strings.Index(xml, open)
	if start < 0 {
		return -1
	}
	sub := xml[start+len(open):]
	end := strings.Index(sub, close)
	if end < 0 {
		return -1
	}
	switch strings.TrimSpace(sub[:end]) {
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

// extractInnerEAPTypeFromXML parses the inner EAP method type used by
// tunneled methods like PEAP (25) or EAP-TTLS (21). The inner method
// appears as a second <EapMethod><Type> inside the outer EAP config.
func extractInnerEAPTypeFromXML(xml string) int {
	first := strings.Index(xml, "<EapMethod>")
	if first < 0 {
		return -1
	}
	rest := xml[first+len("<EapMethod>"):]
	second := strings.Index(rest, "<EapMethod>")
	if second < 0 {
		return -1
	}
	sub := rest[second:]
	typeStart := strings.Index(sub, "<Type")
	if typeStart < 0 {
		return -1
	}
	sub = sub[typeStart:]
	gt := strings.IndexByte(sub, '>')
	if gt < 0 {
		return -1
	}
	sub = sub[gt+1:]
	lt := strings.IndexByte(sub, '<')
	if lt < 0 {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(sub[:lt]))
	if err != nil {
		return -1
	}
	return v
}

// extractTrustedRootCAFromXML parses <TrustedRootCA> hex hashes from the
// ServerValidation section of a WLAN profile XML. These are the SHA-1
// fingerprints of the CA certificates configured for RADIUS server validation.
// Multiple hashes are comma-separated with colon-delimited hex pairs.
func extractTrustedRootCAFromXML(xml string) string {
	var hashes []string
	remaining := xml
	for {
		const open = "<TrustedRootCA>"
		const close = "</TrustedRootCA>"
		start := strings.Index(remaining, open)
		if start < 0 {
			break
		}
		sub := remaining[start+len(open):]
		end := strings.Index(sub, close)
		if end < 0 {
			break
		}
		hex := strings.ReplaceAll(strings.TrimSpace(sub[:end]), " ", "")
		if len(hex) == 40 {
			hashes = append(hashes, formatSHA1Hex(hex))
		}
		remaining = sub[end+len(close):]
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
	const maxChars = 32768
	s := unsafe.Slice(p, maxChars)
	for i, v := range s {
		if v == 0 {
			return syscall.UTF16ToString(s[:i])
		}
	}
	return syscall.UTF16ToString(s)
}

func findWlanInterface(handle uintptr, name string) (*windowsGUID, uint32, error) {
	var listPtr unsafe.Pointer
	ret, _, _ := procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if ret != 0 || listPtr == nil {
		return nil, 0, fmt.Errorf("WlanEnumInterfaces failed: %d", ret)
	}
	defer freeWlanMemory(uintptr(listPtr))

	list := (*wlanInterfaceInfoList)(listPtr)
	if list.NumberOfItems == 0 {
		return nil, 0, fmt.Errorf("no wireless interfaces found")
	}

	headerSize := unsafe.Sizeof(*list)
	itemSize := unsafe.Sizeof(wlanInterfaceInfo{})
	for i := uint32(0); i < list.NumberOfItems; i++ {
		offset := headerSize + uintptr(i)*itemSize
		info := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(list)) + offset))
		desc := utf16ToString(info.StrInterfaceDescription[:])
		if desc == name {
			guid := info.InterfaceGuid
			return &guid, info.IsState, nil
		}
	}
	return nil, 0, fmt.Errorf("wireless interface %q not found", name)
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
