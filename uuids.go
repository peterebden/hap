package hap

import (
	"fmt"

	"tinygo.org/x/bluetooth"
)

// hapCharUUID expands a 16-bit HAP characteristic/service type into its full 128-bit
// UUID. HAP uses the base UUID xxxxxxxx-0000-1000-8000-0026BB765291.
func hapCharUUID(t uint16) bluetooth.UUID {
	u, err := bluetooth.ParseUUID(fmt.Sprintf("%08x-0000-1000-8000-0026bb765291", uint32(t)))
	if err != nil {
		panic(err) // the format string is fixed, so this cannot fail at runtime
	}
	return u
}

// HAP characteristic UUIDs we read or write. The Lightbulb characteristics carry the
// colour state; Pair-Setup/Pair-Verify carry the pairing handshakes.
var (
	CharOn         = hapCharUUID(0x25) // bool
	CharBrightness = hapCharUUID(0x08) // int, 0–100
	CharHue        = hapCharUUID(0x13) // float, 0–360 degrees
	CharSaturation = hapCharUUID(0x2f) // float, 0–100 percent

	CharPairSetup  = hapCharUUID(0x4c)
	CharPairVerify = hapCharUUID(0x4e)
)

// descCharInstanceID is the GATT descriptor that holds a characteristic's HAP instance
// ID (HAP spec §7.4.4.5.2). Reading it is the reason we need descriptor support in the
// BLE transport.
var descCharInstanceID = func() bluetooth.UUID {
	u, err := bluetooth.ParseUUID("dc46f0fe-81d2-4616-b5d9-6abdd796939a")
	if err != nil {
		panic(err)
	}
	return u
}()
