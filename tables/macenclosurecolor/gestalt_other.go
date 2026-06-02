//go:build !darwin

package macenclosurecolor

// noopGestalt is used on non-darwin platforms, where MobileGestalt does not
// exist. mac_enclosure_color is only registered on darwin (see main.go), but
// this package is imported unconditionally, so it must compile everywhere.
type noopGestalt struct{}

func newGestalt() Gestalt                        { return noopGestalt{} }
func (noopGestalt) Int(string) (int, bool)       { return 0, false }
func (noopGestalt) String(string) (string, bool) { return "", false }
