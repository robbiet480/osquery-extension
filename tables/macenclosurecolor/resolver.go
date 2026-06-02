package macenclosurecolor

// colorRule is one ordered matching rule. The first rule whose non-empty fields
// all match wins. An empty ProductType / ModelName means "any". HasCode
// indicates whether Code should be matched at all; false means the rule applies
// regardless of the DeviceEnclosureColor value.
type colorRule struct {
	ProductType string
	ModelName   string
	Code        int
	HasCode     bool
	Color       string
}

// colorRules maps a Mac's identifying fields to its human-readable enclosure
// color. Order matters: model-specific rules MUST precede universal-code rules
// so they take precedence (e.g. iMac + code 3 -> "Yellow" before any universal
// code rule).
//
// WHY THIS IS A HARDCODED TABLE (and not derived programmatically): macOS does
// not expose the enclosure color *name* anywhere. The private MobileGestalt
// DeviceEnclosureColor key returns only a numeric code, and that code is
// ambiguous across models — code 3 is "Yellow" on iMac but "Gold" on MacBook
// Air; code 7 is "Purple" vs "Midnight"; code 8 is "Orange" vs "Starlight" —
// so the code alone cannot yield a name without model context. system_profiler
// and ioreg carry no color field on Apple Silicon, and post-2021 serial numbers
// are randomized (no config-code decode). The canonical community reference,
// munkireport/ibridge, hardcodes this exact model-conditioned table for the
// same reason:
// https://github.com/munkireport/ibridge/blob/master/scripts/ibridge.py
//
// To update when Apple ships a new color: add a rule below mirroring ibridge.
// The raw code is always exposed as the color_code column, so an unmapped color
// still surfaces (as code N / "Unknown") without a code change.
var colorRules = []colorRule{
	// Model-forced (no code lookup needed).
	{ProductType: "Macmini8,1", Color: "Space Gray"},
	{ProductType: "iMacPro1,1", Color: "Space Gray"},
	{ProductType: "iMac20,1", Color: "Silver"},
	{ProductType: "iMac20,2", Color: "Silver"},
	{ModelName: "Mac mini", Color: "Silver"},
	{ModelName: "Mac Pro", Color: "Silver"},
	{ModelName: "Mac Studio", Color: "Silver"},

	// Model-disambiguated codes (same code, different color by model).
	{ModelName: "iMac", Code: 3, HasCode: true, Color: "Yellow"},
	{ModelName: "MacBook Air", Code: 3, HasCode: true, Color: "Gold"},
	{ModelName: "iMac", Code: 7, HasCode: true, Color: "Purple"},
	{ModelName: "MacBook Air", Code: 7, HasCode: true, Color: "Midnight"},
	{ModelName: "iMac", Code: 8, HasCode: true, Color: "Orange"},
	{ModelName: "MacBook Air", Code: 8, HasCode: true, Color: "Starlight"},

	// Universal codes (apply to every model).
	{Code: 1, HasCode: true, Color: "Silver"},
	{Code: 2, HasCode: true, Color: "Space Gray"},
	{Code: 4, HasCode: true, Color: "Green"},
	{Code: 5, HasCode: true, Color: "Blue"},
	{Code: 6, HasCode: true, Color: "Red"},
	{Code: 9, HasCode: true, Color: "Space Black"},
	{Code: 11, HasCode: true, Color: "Sky Blue"},
	{Code: 12, HasCode: true, Color: "Indigo"},
	{Code: 13, HasCode: true, Color: "Citrus"},
	{Code: 14, HasCode: true, Color: "Blush"},
}

// resolveColor returns the human-readable color name for a Mac given its
// product type (e.g. "Mac16,5"), model name (e.g. "MacBook Pro"), and numeric
// DeviceEnclosureColor. codeKnown is false when MobileGestalt did not return a
// code (entitlement-gated or missing); rules requiring a code are skipped then.
func resolveColor(productType, model string, code int, codeKnown bool) string {
	for _, r := range colorRules {
		if r.ProductType != "" && r.ProductType != productType {
			continue
		}
		if r.ModelName != "" && r.ModelName != model {
			continue
		}
		if r.HasCode {
			if !codeKnown || r.Code != code {
				continue
			}
		}
		return r.Color
	}
	return "Unknown"
}
