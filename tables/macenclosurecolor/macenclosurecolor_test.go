package macenclosurecolor

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGestalt is a deterministic in-memory Gestalt for tests.
type fakeGestalt struct {
	ints    map[string]int
	strings map[string]string
}

func (f fakeGestalt) Int(key string) (int, bool) {
	v, ok := f.ints[key]
	return v, ok
}

func (f fakeGestalt) String(key string) (string, bool) {
	v, ok := f.strings[key]
	return v, ok
}

func TestParseModelName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
		want string
	}{
		{"MacBook Pro", `{"SPHardwareDataType":[{"machine_name":"MacBook Pro","machine_model":"Mac16,5"}]}`, "MacBook Pro"},
		{"Mac Studio", `{"SPHardwareDataType":[{"machine_name":"Mac Studio"}]}`, "Mac Studio"},
		{"empty array", `{"SPHardwareDataType":[]}`, ""},
		{"missing key", `{}`, ""},
		{"malformed", `not json`, ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, parseModelName([]byte(c.json)), c.name)
	}
}

func TestResolveColor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		productType string
		model       string
		code        int
		codeKnown   bool
		want        string
	}{
		// Model-forced rules (no code).
		{"Mac Studio is Silver", "Mac16,9", "Mac Studio", 0, false, "Silver"},
		{"Mac mini is Silver", "Mac16,10", "Mac mini", 0, false, "Silver"},
		{"iMacPro is Space Gray", "iMacPro1,1", "iMac Pro", 0, false, "Space Gray"},
		// Model-disambiguated codes: same code, different color by model.
		{"iMac code 3 is Yellow", "iMac21,1", "iMac", 3, true, "Yellow"},
		{"MBA code 3 is Gold", "MacBookAir9,1", "MacBook Air", 3, true, "Gold"},
		{"iMac code 7 is Purple", "iMac21,1", "iMac", 7, true, "Purple"},
		{"MBA code 7 is Midnight", "Mac14,2", "MacBook Air", 7, true, "Midnight"},
		{"iMac code 8 is Orange", "iMac21,1", "iMac", 8, true, "Orange"},
		{"MBA code 8 is Starlight", "Mac14,2", "MacBook Air", 8, true, "Starlight"},
		// Universal codes.
		{"code 9 is Space Black", "Mac16,5", "MacBook Pro", 9, true, "Space Black"},
		{"code 11 is Sky Blue", "Mac16,12", "MacBook Air", 11, true, "Sky Blue"},
		{"code 2 is Space Gray", "MacBookPro18,1", "MacBook Pro", 2, true, "Space Gray"},
		// Unknown / missing code.
		{"unknown code", "Mac16,5", "MacBook Pro", 99, true, "Unknown"},
		{"no code, no model rule", "Unknown1,1", "Mystery Mac", 0, false, "Unknown"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, resolveColor(c.productType, c.model, c.code, c.codeKnown), c.name)
	}
}

func TestGenerateRows(t *testing.T) {
	t.Parallel()
	g := fakeGestalt{
		ints:    map[string]int{"DeviceEnclosureColor": 9},
		strings: map[string]string{"ProductType": "Mac16,5"},
	}
	cmder := utils.MockCmdRunner{Output: `{"SPHardwareDataType":[{"machine_name":"MacBook Pro"}]}`}

	rows, err := GenerateRows(g, func() string { return readModelName(cmder) })
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "Space Black", rows[0]["color"])
	assert.Equal(t, "9", rows[0]["color_code"])
	assert.Equal(t, "MacBook Pro", rows[0]["model"])
	assert.Equal(t, "Mac16,5", rows[0]["product_type"])
}

func TestGenerateRows_CodeAbsentOmitsColumn(t *testing.T) {
	t.Parallel()
	// No DeviceEnclosureColor from MobileGestalt: color_code must be omitted
	// (NULL), but model-forced rules still resolve a color.
	g := fakeGestalt{
		ints:    map[string]int{}, // no code
		strings: map[string]string{"ProductType": "Mac16,9"},
	}
	cmder := utils.MockCmdRunner{Output: `{"SPHardwareDataType":[{"machine_name":"Mac Studio"}]}`}

	rows, err := GenerateRows(g, func() string { return readModelName(cmder) })
	require.NoError(t, err)
	_, hasCode := rows[0]["color_code"]
	assert.False(t, hasCode, "color_code must be omitted when the code is unknown")
	assert.Equal(t, "Silver", rows[0]["color"])
}

func TestGenerateRows_SystemProfilerError(t *testing.T) {
	t.Parallel()
	// system_profiler fails: model is empty, but a code-based universal rule
	// still resolves and product_type/color_code still report.
	g := fakeGestalt{
		ints:    map[string]int{"DeviceEnclosureColor": 5},
		strings: map[string]string{"ProductType": "Mac16,5"},
	}
	cmder := utils.MockCmdRunner{Err: assertErr{}}

	rows, err := GenerateRows(g, func() string { return readModelName(cmder) })
	require.NoError(t, err)
	assert.Equal(t, "", rows[0]["model"])
	assert.Equal(t, "Blue", rows[0]["color"])
	assert.Equal(t, "5", rows[0]["color_code"])
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }

func TestColumns(t *testing.T) {
	t.Parallel()
	want := []string{"color", "color_code", "model", "product_type"}
	cols := MacEnclosureColorColumns()
	require.Len(t, cols, len(want))
	for i, c := range cols {
		assert.Equal(t, want[i], c.Name)
	}
}
