//go:build darwin

package macenclosurecolor

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the real cgo MobileGestalt path (gestalt_darwin.go).
// MobileGestalt values are hardware-dependent, so the tests assert the
// interface contract and structural invariants rather than specific colors:
// the bridge must load, return without panicking, and produce values
// consistent with the host (e.g. ProductType matching `sysctl hw.model`).

func TestNewGestalt_Loads(t *testing.T) {
	g := newGestalt()
	require.NotNil(t, g, "newGestalt must always return a usable Gestalt")
	// A missing key must report not-present, never panic.
	_, ok := g.String("ThisKeyDoesNotExist_xyzzy")
	assert.False(t, ok, "an unknown key must report not-present")
	_, ok = g.Int("ThisKeyDoesNotExist_xyzzy")
	assert.False(t, ok, "an unknown int key must report not-present")
}

func TestMobileGestalt_ProductTypeMatchesHardware(t *testing.T) {
	g := newGestalt()
	productType, ok := g.String("ProductType")
	if !ok {
		// MGCopyAnswer for ProductType can be entitlement-gated in some
		// contexts; skip rather than fail if the host denies it.
		t.Skip("MobileGestalt ProductType not available in this context")
	}
	require.NotEmpty(t, productType)

	out, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	require.NoError(t, err)
	hwModel := strings.TrimSpace(string(out))

	// ProductType from MobileGestalt should equal hw.model (both are the
	// model identifier, e.g. "Mac16,5").
	assert.Equal(t, hwModel, productType,
		"MobileGestalt ProductType should match sysctl hw.model")
}

func TestMobileGestalt_EnclosureColorIsSaneOrAbsent(t *testing.T) {
	g := newGestalt()
	code, ok := g.Int("DeviceEnclosureColor")
	if !ok {
		// Not all Macs / contexts expose the code; absence is valid.
		t.Skip("DeviceEnclosureColor not available on this host")
	}
	// When present it is a small non-negative code (the documented range is
	// 1..14; allow some headroom for future codes).
	assert.GreaterOrEqual(t, code, 0)
	assert.Less(t, code, 100, "enclosure color code should be a small integer")
}

// TestGenerateRows_RealHost runs the full table against the real host (cgo
// Gestalt + real system_profiler) and asserts the row is well-formed. It does
// not assert a specific color, since that depends on the test machine.
func TestGenerateRows_RealHost(t *testing.T) {
	rows, err := MacEnclosureColorGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	row := rows[0]
	// product_type should match hw.model on a real Mac.
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(out)), row["product_type"])
	// color is always set (a name or "Unknown"); never empty.
	assert.NotEmpty(t, row["color"])
}
