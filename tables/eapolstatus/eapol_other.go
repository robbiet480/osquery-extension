//go:build !darwin

package eapolstatus

import "fmt"

func newBackend() EAPOLBackend {
	return noopBackend{}
}

type noopBackend struct{}

func (noopBackend) GetStatus(ifname string) (EAPOLStatus, error) {
	return EAPOLStatus{Interface: ifname}, fmt.Errorf("%w: EAP8021X framework not available on this platform", ErrBackendUnavailable)
}
