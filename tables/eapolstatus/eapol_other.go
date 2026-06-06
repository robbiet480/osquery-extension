//go:build !darwin && !windows

package eapolstatus

import (
	"fmt"
	"strconv"
)

func newBackend() EAPOLBackend {
	return noopBackend{}
}

type noopBackend struct{}

func (noopBackend) GetStatus(ifname string) (EAPOLStatus, error) {
	return EAPOLStatus{Interface: ifname}, fmt.Errorf("%w: EAP8021X framework not available on this platform", ErrBackendUnavailable)
}

func defaultInterfaces() []string {
	ifaces := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ifaces = append(ifaces, "en"+strconv.Itoa(i))
	}
	return ifaces
}
