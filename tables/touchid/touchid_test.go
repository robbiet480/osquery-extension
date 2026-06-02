package touchid

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real `bioutil -r -s` output on Apple Silicon (macOS 15+). The extra timeout
// lines would trip position-based parsing.
const systemBioutil = `System Touch ID configuration:
	Biometrics functionality: 1
	Biometrics for unlock: 1
	Biometric timeout (in seconds): 172800
	Match timeout (in seconds): 14400
	Passcode input timeout (in seconds): 561600
Operation performed successfully.`

const userBioutil = `User Touch ID configuration:
	Biometrics for unlock: 1
	Biometrics for ApplePay: 1
	Effective biometrics for unlock: 1
	Effective biometrics for ApplePay: 1
Operation performed successfully.`

// `bioutil -c -s` (root): one line per enrolled user.
const allCounts = "User 501:\t1 biometric template(s)\nUser 503:\t2 biometric template(s)\nOperation performed successfully."

// `sysctl -n hw.model` output: the SoC / model identifier, with a trailing
// newline (reported as secure_enclave).
const sysctlModel = "Mac16,5\n"

const dsclUsers = "_mbsetupuser  248\nroot  0\nalice  501\nbob  503\n"

// A minimal `ioreg -a -r -c <class>` plist: an array with one matched node.
// ioreg emits a plist array of matched IORegistry entries; for presence we only
// need len(array) > 0.
const ioregOneNode = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>IOClass</key>
		<string>AppleMesaAccessory</string>
	</dict>
</array>
</plist>`

// `ioreg -a -r -c <class>` for a class with no instances: empty output.
const ioregNoNode = ``

func TestParseBioutil(t *testing.T) {
	t.Parallel()
	f := parseBioutil([]byte(systemBioutil))
	assert.Equal(t, "1", f["Biometrics functionality"])
	assert.Equal(t, "1", f["Biometrics for unlock"])
	_, hasHeader := f["System Touch ID configuration"]
	assert.False(t, hasHeader, "header line should not parse as a field")
	_, hasFooter := f["Operation performed successfully"]
	assert.False(t, hasFooter, "footer line should not parse as a field")
}

func TestParseFingerprintCounts(t *testing.T) {
	t.Parallel()
	got := parseFingerprintCounts([]byte(allCounts))
	assert.Equal(t, map[string]int{"501": 1, "503": 2}, got)

	single := parseFingerprintCounts([]byte("User 501:\t3 biometric template(s)\nOperation performed successfully."))
	assert.Equal(t, 3, single["501"])

	assert.Empty(t, parseFingerprintCounts([]byte("nonsense\nOperation performed successfully.")))
}

func TestParseLocalUIDs(t *testing.T) {
	t.Parallel()
	// Only human-range uids (501, 503) survive; system accounts are dropped.
	assert.Equal(t, []string{"501", "503"}, parseLocalUIDs([]byte(dsclUsers)))
}

func TestIORegClassPresent(t *testing.T) {
	t.Parallel()
	present := utils.MockCmdRunner{Output: ioregOneNode}
	ok, err := ioregClassPresent(present, "AppleMesaAccessory")
	require.NoError(t, err)
	assert.True(t, ok)

	absent := utils.MockCmdRunner{Output: ioregNoNode}
	ok, err = ioregClassPresent(absent, "AppleBiometricSensor")
	require.NoError(t, err)
	assert.False(t, ok)
}

// systemRunner mocks every command GetSystemConfig issues. builtinIOReg and
// mesaIOReg are the canned `ioreg -a -r -c <class>` outputs for the two classes.
func systemRunner(builtinIOReg, mesaIOReg string) utils.MultiMockCmdRunner {
	return utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/sbin/sysctl -n hw.model":                  {Output: sysctlModel},
			"/usr/bin/bioutil -r -s":                        {Output: systemBioutil},
			"/usr/sbin/ioreg -a -r -c AppleBiometricSensor": {Output: builtinIOReg},
			"/usr/sbin/ioreg -a -r -c AppleMesaAccessory":   {Output: mesaIOReg},
		},
	}
}

func TestGetSystemConfig_BuiltInSensor(t *testing.T) {
	t.Parallel()
	// Laptop: built-in AppleBiometricSensor present.
	cfg, err := GetSystemConfig(systemRunner(ioregOneNode, ioregNoNode))
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Compatible)
	assert.Equal(t, "Mac16,5", cfg.SecureEnclave)
	assert.Equal(t, "1", cfg.Enabled)
	assert.Equal(t, "1", cfg.Unlock)
	assert.Equal(t, "1", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetSystemConfig_AccessorySensor(t *testing.T) {
	t.Parallel()
	// Desktop with a Magic Keyboard with Touch ID: no built-in sensor, but an
	// AppleMesaAccessory node is present.
	cfg, err := GetSystemConfig(systemRunner(ioregNoNode, ioregOneNode))
	require.NoError(t, err)
	assert.Equal(t, "0", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetSystemConfig_NoSensor(t *testing.T) {
	t.Parallel()
	// Keyboard-less Mac mini / Studio: no sensor of any kind.
	cfg, err := GetSystemConfig(systemRunner(ioregNoNode, ioregNoNode))
	require.NoError(t, err)
	assert.Equal(t, "0", cfg.Builtin)
	assert.Equal(t, "0", cfg.SensorPresent)
	// bioutil still reports compatible=1 (on-die Secure Enclave) — which is
	// exactly why touchid_compatible is not a usable sensor-presence signal.
	assert.Equal(t, "1", cfg.Compatible)
}

func TestGetSystemConfig_BioutilError(t *testing.T) {
	t.Parallel()
	// bioutil fails, but the ioreg-derived columns must still be populated.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/sbin/sysctl -n hw.model":                  {Output: sysctlModel},
			"/usr/bin/bioutil -r -s":                        {Err: errors.New("boom")},
			"/usr/sbin/ioreg -a -r -c AppleBiometricSensor": {Output: ioregOneNode},
			"/usr/sbin/ioreg -a -r -c AppleMesaAccessory":   {Output: ioregNoNode},
		},
	}
	cfg, err := GetSystemConfig(runner)
	require.NoError(t, err)
	assert.Equal(t, "Mac16,5", cfg.SecureEnclave)
	assert.Equal(t, "0", cfg.Compatible) // unknown -> default 0
	assert.Equal(t, "1", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetUserConfigs_AllAccounts(t *testing.T) {
	t.Parallel()
	// -c -s reports 501=1, 503=2; 502 absent => 0. Only 501 is "logged in"
	// (its -r succeeds); the others' -r errors but their counts still report.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s":                {Output: allCounts},
			"/usr/bin/dscl . -list /Users UniqueID": {Output: "alice 501\ncarol 502\nbob 503\n"},
		},
	}
	perUser := func(uid string) ([]byte, error) {
		if uid == "501" {
			return []byte(userBioutil), nil
		}
		return nil, errors.New("not logged in")
	}
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, exists, nil, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 3)

	byUID := map[string]*UserConfig{}
	for _, c := range configs {
		byUID[c.UID] = c
	}
	// 501: logged in, 1 fingerprint, flags populated.
	assert.Equal(t, "1", byUID["501"].FingerprintsRegistered)
	assert.Equal(t, "1", byUID["501"].Unlock)
	// 502: absent from -c -s => known 0; logged out => flags empty (NULL).
	assert.Equal(t, "0", byUID["502"].FingerprintsRegistered)
	assert.Equal(t, "", byUID["502"].Unlock)
	// 503: 2 fingerprints; logged out => flags empty.
	assert.Equal(t, "2", byUID["503"].FingerprintsRegistered)
	assert.Equal(t, "", byUID["503"].Unlock)
}

func TestGetUserConfigs_ConstraintAndZeroForcesEffective(t *testing.T) {
	t.Parallel()
	// uid 501 constrained; -c -s reports nobody enrolled (known 0). bioutil -r
	// claims effective=1, which the zero-fingerprint workaround must force to 0.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Output: "Operation performed successfully."},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, exists, []string{"501"}, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	c := configs[0]
	assert.Equal(t, "0", c.FingerprintsRegistered)
	assert.Equal(t, "0", c.EffectiveUnlock)
	assert.Equal(t, "0", c.EffectiveApplePay)
	// Configured (non-effective) flags stay as bioutil reported.
	assert.Equal(t, "1", c.Unlock)
}

func TestGetUserConfigs_CountUnknownPreservesEffective(t *testing.T) {
	t.Parallel()
	// -c -s fails (not root): count unknown. effective flags must be preserved
	// (the zero-fingerprint workaround must NOT fire on unknown counts).
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Err: errors.New("not root")},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, exists, []string{"501"}, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	c := configs[0]
	assert.Equal(t, "", c.FingerprintsRegistered) // unknown -> empty
	assert.Equal(t, "1", c.EffectiveUnlock)
}

func TestGetUserConfigs_SkipsNonexistentUID(t *testing.T) {
	t.Parallel()
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Output: allCounts},
		},
	}
	perUser := func(string) ([]byte, error) { return nil, errors.New("nope") }
	exists := func(string) bool { return false }

	configs, err := GetUserConfigs(runner, exists, []string{"99999"}, perUser)
	require.NoError(t, err)
	assert.Empty(t, configs)
}

func columnNames(cols []table.ColumnDefinition) []string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	return names
}

func TestColumns(t *testing.T) {
	t.Parallel()
	// Compare full name slices so a count/order mismatch is a clean assertion
	// failure rather than an index-out-of-range panic.
	wantSys := []string{"touchid_compatible", "secure_enclave", "touchid_enabled", "touchid_unlock", "touchid_builtin", "touchid_sensor_present"}
	assert.Equal(t, wantSys, columnNames(TouchIDSystemConfigColumns()))

	wantUsr := []string{"uid", "fingerprints_registered", "touchid_unlock", "touchid_applepay", "effective_unlock", "effective_applepay"}
	assert.Equal(t, wantUsr, columnNames(TouchIDUserConfigColumns()))
}
