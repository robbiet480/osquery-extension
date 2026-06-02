// Package macenclosurecolor implements the mac_enclosure_color osquery table,
// which reports the running Mac's enclosure (chassis) color — e.g. "Space
// Black", "Sky Blue", "Midnight", "Silver".
//
// The color name is not exposed by macOS in any directly-readable form. Apple
// surfaces only a numeric DeviceEnclosureColor code via the private
// MobileGestalt API (read here via cgo on darwin), and that code is ambiguous
// across models (code 3 is "Yellow" on iMac but "Gold" on MacBook Air), so a
// model-aware mapping is required to turn it into a name. system_profiler and
// ioreg do not carry the color at all on Apple Silicon. The mapping in
// resolver.go mirrors the canonical community reference, munkireport/ibridge,
// which hardcodes the same table for the same reason. The raw code is also
// exposed as color_code so consumers can map it themselves or alert on
// "Unknown" without depending on this table's name coverage being complete.
//
// Apple Silicon and Intel macOS only. On non-darwin platforms the table is not
// registered; the package still compiles via a no-op Gestalt stub.
package macenclosurecolor

import (
	"context"
	"strconv"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

// Gestalt is the minimal subset of MobileGestalt this table needs. The
// interface exists so the resolver can be unit-tested with an in-memory fake;
// the production darwin implementation (gestalt_darwin.go) calls
// /usr/lib/libMobileGestalt.dylib via cgo.
type Gestalt interface {
	// Int returns the integer value for key and whether the key was present
	// with a numeric (or numeric-castable) value.
	Int(key string) (int, bool)
	// String returns the string value for key and whether the key was present.
	String(key string) (string, bool)
}

// MacEnclosureColorColumns is the schema for mac_enclosure_color.
func MacEnclosureColorColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("color"),         // resolved human name, or "Unknown"
		table.IntegerColumn("color_code"), // raw DeviceEnclosureColor; empty if absent
		table.TextColumn("model"),         // Model Name, e.g. "MacBook Pro"
		table.TextColumn("product_type"),  // ProductType, e.g. "Mac16,5"
	}
}

// GenerateRows builds the single mac_enclosure_color row. All external
// dependencies are injected so the logic is unit-testable without cgo or
// subprocesses.
func GenerateRows(g Gestalt, cmder utils.CmdRunner) ([]map[string]string, error) {
	productType, _ := g.String("ProductType")
	code, codeKnown := g.Int("DeviceEnclosureColor")

	// MobileGestalt's marketing-name keys return the OS name ("macOS") on
	// recent macOS, so the Model Name comes from system_profiler instead.
	model := ""
	if out, err := cmder.RunCmd("/usr/sbin/system_profiler", "SPHardwareDataType", "-json"); err == nil {
		model = parseModelName(out)
	}

	row := map[string]string{
		"color":        resolveColor(productType, model, code, codeKnown),
		"model":        model,
		"product_type": productType,
	}
	if codeKnown {
		row["color_code"] = strconv.Itoa(code)
	}
	return []map[string]string{row}, nil
}

// MacEnclosureColorGenerate is the osquery generate function. It wires up the
// production Gestalt (cgo on darwin, no-op elsewhere) and command runner.
func MacEnclosureColorGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return GenerateRows(newGestalt(), utils.NewRunner().Runner)
}
