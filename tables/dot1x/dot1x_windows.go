//go:build windows

package dot1x

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file holds only the wlanapi.dll syscall plumbing. The status logic it
// feeds lives in dot1x_wlan.go (wlanStatus), which is tested on every platform.

const (
	wlanClientVersion = 2

	wlanIntfOpcodeCurrentConnection uint32 = 7
)

type wlanInterfaceInfo struct {
	InterfaceGuid           windowsGUID
	StrInterfaceDescription [256]uint16
	IsState                 uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

var (
	// NewLazySystemDLL (not NewLazyDLL) forces loading from the Windows system
	// directory, avoiding DLL search-order hijacking if the process runs from a
	// writable location.
	modWlanapi = windows.NewLazySystemDLL("wlanapi.dll")

	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetProfile     = modWlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	wlanOnce sync.Once
	// wlanAvail reports whether wlanapi.dll loaded and every proc resolved.
	// Only DLL/proc resolution is cached for the process lifetime; the client
	// handle is opened per table generation (see windowsBackend) so the
	// extension recovers if wlansvc was down or restarts.
	wlanAvail bool
	// wlanInitErr records why initWlan failed (DLL load or missing proc), so
	// unavailableBackend can report a specific reason.
	wlanInitErr error
)

func initWlan() {
	if err := modWlanapi.Load(); err != nil {
		wlanInitErr = fmt.Errorf("loading wlanapi.dll: %w", err)
		return
	}
	for _, p := range []*windows.LazyProc{
		procWlanOpenHandle, procWlanCloseHandle, procWlanEnumInterfaces,
		procWlanQueryInterface, procWlanGetProfile, procWlanFreeMemory,
	} {
		if err := p.Find(); err != nil {
			wlanInitErr = fmt.Errorf("resolving wlanapi.dll proc %s: %w", p.Name, err)
			return
		}
	}
	wlanAvail = true
}

// windowsBackend implements wlanClient for one table generation. On first use
// it opens a WLAN client handle and snapshots all interfaces (both the
// description->info map and the ordered names) so the generation enumerates
// only once — shared between the default interface list and every GetStatus.
// Close releases the handle.
type windowsBackend struct {
	handle  uintptr
	once    sync.Once
	ifaces  map[string]ifaceInfo
	names   []string
	enumErr error
}

func newBackend() Dot1XBackend {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return unavailableBackend{}
	}
	return &windowsBackend{}
}

type unavailableBackend struct{}

func (unavailableBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	if wlanInitErr != nil {
		return Dot1XStatus{Interface: ifname},
			fmt.Errorf("%w: Windows WLAN backend unavailable: %w", ErrBackendUnavailable, wlanInitErr)
	}
	return Dot1XStatus{Interface: ifname},
		fmt.Errorf("%w: Windows WLAN backend unavailable", ErrBackendUnavailable)
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
	if ret != 0 {
		return nil, nil, fmt.Errorf("WlanEnumInterfaces failed: %w", syscall.Errno(ret))
	}
	if listPtr == nil {
		return nil, nil, fmt.Errorf("WlanEnumInterfaces succeeded but returned no interface list")
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
		key := uniqueIfaceKey(infos, desc, info.InterfaceGuid)
		infos[key] = ifaceInfo{guid: info.InterfaceGuid, state: info.IsState}
		names = append(names, key)
	}
	return infos, names, nil
}

// uniqueIfaceKey returns desc, or a GUID-disambiguated key when desc already
// exists in seen. Windows can report two adapters with identical interface
// descriptions (e.g. two identical USB Wi-Fi dongles); without this the later
// one would overwrite the earlier in the snapshot map, dropping it from
// results and making it unqueryable. Suffixing the stable GUID keeps each
// physical adapter individually enumerable and targetable via
// WHERE interface = '...'.
func uniqueIfaceKey(seen map[string]ifaceInfo, desc string, guid windowsGUID) string {
	if _, dup := seen[desc]; !dup {
		return desc
	}
	return desc + " " + guid.String()
}

// enumerateWlanInterfaces returns the descriptions of all wireless interfaces.
func enumerateWlanInterfaces() []string {
	b, ok := newBackend().(*windowsBackend)
	if !ok {
		return nil
	}
	defer b.Close() //nolint:errcheck
	return b.interfaceNames()
}

func defaultInterfaces() []string {
	// Return enumerateWlanInterfaces' result as-is so the nil/empty distinction
	// is preserved: nil means WLAN is unavailable or enumeration failed
	// (defaults unknown -> caller's generic fallback), while a non-nil empty
	// slice means "successfully enumerated, no wireless adapters" (query none).
	return enumerateWlanInterfaces()
}

// interfaces lazily opens the client handle and enumerates interfaces once
// per backend instance (i.e. once per table generation), caching both the
// info map and ordered names. A WlanOpenHandle failure is reported like an
// enumeration failure (backend unavailable for this generation); the next
// generation retries with a fresh backend.
func (b *windowsBackend) interfaces() (map[string]ifaceInfo, []string, error) {
	b.once.Do(func() {
		h, err := openWlanHandle()
		if err != nil {
			b.enumErr = fmt.Errorf("opening WLAN client handle: %w", err)
			return
		}
		b.handle = h
		b.ifaces, b.names, b.enumErr = enumerateWlanInterfaceInfos(h)
	})
	return b.ifaces, b.names, b.enumErr
}

// interfaceNames satisfies the shared interfaceLister optional interface so the
// default interface list for an unconstrained query is sourced from the same
// snapshot GetStatus uses, avoiding a second WlanEnumInterfaces call. Returns
// nil when WLAN is unavailable / enumeration failed (caller's generic
// fallback), or a possibly-empty slice of adapter names otherwise.
func (b *windowsBackend) interfaceNames() []string {
	_, names, err := b.interfaces()
	if err != nil {
		return nil
	}
	return names
}

func (b *windowsBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	return wlanStatus(b, ifname)
}

// Close releases the WLAN client handle, if one was opened.
func (b *windowsBackend) Close() error {
	if b.handle == 0 {
		return nil
	}
	ret, _, _ := procWlanCloseHandle.Call(b.handle, 0)
	b.handle = 0
	if ret != 0 {
		return fmt.Errorf("WlanCloseHandle failed: %w", syscall.Errno(ret))
	}
	return nil
}

// currentConnection queries WLAN_CONNECTION_ATTRIBUTES for guid and returns a
// copy of the raw buffer (the wlanapi allocation is freed before returning).
func (b *windowsBackend) currentConnection(guid windowsGUID) ([]byte, error) {
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
		return nil, syscall.Errno(ret)
	}
	if dataPtr == nil {
		return nil, nil
	}
	defer freeWlanMemory(uintptr(dataPtr))
	return append([]byte(nil), unsafe.Slice((*byte)(dataPtr), dataSize)...), nil
}

// profileXML calls WlanGetProfile and returns the profile XML string.
func (b *windowsBackend) profileXML(guid windowsGUID, profileName string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(profileName)
	if err != nil {
		return "", err
	}
	var xmlPtr *uint16
	var flags uint32
	ret, _, _ := procWlanGetProfile.Call(
		b.handle,
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&xmlPtr)),
		uintptr(unsafe.Pointer(&flags)),
		0,
	)
	if ret != 0 {
		return "", fmt.Errorf("WlanGetProfile failed: %w", syscall.Errno(ret))
	}
	if xmlPtr == nil {
		return "", fmt.Errorf("WlanGetProfile succeeded but returned no profile XML")
	}
	defer freeWlanMemory(uintptr(unsafe.Pointer(xmlPtr)))
	return utf16PtrToString(xmlPtr), nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}
