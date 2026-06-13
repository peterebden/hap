# hap

[![Go Reference](https://pkg.go.dev/badge/github.com/peterebden/hap.svg)](https://pkg.go.dev/github.com/peterebden/hap)

A small **HomeKit Accessory Protocol over Bluetooth LE (HAP-BLE) controller** for Go.

This lets a program act as the controller side of HomeKit: pair with a
HAP accessory using its 8-digit setup code, re-establish an encrypted session on each
connection, and read or write the accessory's characteristics - for example to drive a
HomeKit light bulb's on/off, brightness, hue and saturation.

It is the controller counterpart to server-side libraries like
[`brutella/hap`](https://github.com/brutella/hap): that one *is* an accessory, this one
*controls* one.

## Status & requirements

This package implements the BLE transport of HAP only (not IP/Wi-Fi or Thread),
and the GATT plumbing is currently built on [`tinygo.org/x/bluetooth`](https://tinygo.org/x/bluetooth)
using the Linux/BlueZ backend.

The protocol core (TLV8, PDU framing, SRP, the pairing state machines, the session cipher)
is portable, pure Go; only the Transport is platform-specific.

This requires GATT descriptor reads to retrieve a characteristic's HAP instance ID,
which is currently an open PR to the upstream `tinygo.org/x/bluetooth` repo. For now you
must point to a fork with that addition in your `go.mod`:

```
replace tinygo.org/x/bluetooth => github.com/peterebden/bluetooth v0.0.0-20260613101853-cb4d5a8ba18e
```

## Gory HAP-BLE details

A HomeKit accessory exposes its features as GATT characteristics (On `0x25`, Brightness
`0x08`, Hue `0x13`, Saturation `0x2F`, …), but they are **not** readable or writable
directly — HAP wraps every access in its own protocol layered on top of GATT:

1. **Pairing identifiers (instance IDs).** Every HAP request addresses a characteristic by a
   16-bit *instance ID*, which the accessory publishes in a GATT *descriptor*
   (`DC46F0FE-...`). This is why descriptor reads are required.
2. **Pair-Setup** (once per accessory). An [SRP-6a](https://datatracker.ietf.org/doc/html/rfc5054)
   password-authenticated key exchange using the 8-digit setup code, after which controller and accessory
   have exchanged long-term Ed25519 identity keys. The result - `PairingData` - can be persisted and reused forever.
3. **Pair-Verify** (every connection). A Curve25519 (X25519) key exchange, mutually
   authenticated with the long-term keys from pairing, yielding fresh per-session keys.
4. **Secure session.** All subsequent characteristic reads/writes are framed as HAP PDUs and
   encrypted with ChaCha20-Poly1305 under per-direction counters.

This package implements all four steps.

### A note on BlueZ fragmentation

BlueZ performs ATT long *reads* transparently, so the transport reads a whole HAP response
PDU in one call; but accessories tested here reject ATT long *writes*, so requests larger
than one ATT payload are split into HAP continuation fragments. The transport handles both
sides of this asymmetry; callers never see fragments.

## Usage

### 1. Get a connected `bluetooth.Device`

You bring your own scanning/connection logic with tinygo bluetooth; this package takes it
from there. HomeKit accessories rotate a random BLE address, so match by advertised name
rather than a fixed MAC, and - if several accessories share a name - identify the right one
by which one `Verify` succeeds against.

```go
adapter := bluetooth.DefaultAdapter
if err := adapter.Enable(); err != nil {
    return err
}
device, err := adapter.Connect(address, bluetooth.ConnectionParams{})
// Or adapter.Scan() to find the device
```

### 2. Pair once, and persist the result

The accessory must be **unpaired** (factory state). HAP allows only one self-pairing: if it
is already paired to a phone/hub, pair-setup is refused until it is removed there or reset.

```go
t, err := hap.NewTransport(device)
if err != nil {
    return err
}

pd, err := hap.Pair(t, "123-45-678") // 8 digit device pairing code; dashes optional
if err != nil {
    return err
}

if err := pd.SaveToFile("pairing.json"); err != nil {
    return err
}
```

`PairingData` contains a **private key** (`ControllerLTSK`), so should be treated as a secret.

### 3. Reconnect: verify and control

On every later connection, load the saved pairing, verify, and use the `Session`:

```go
pd, err := hap.LoadPairingDataFromFile("pairing.json")
if err != nil {
    return err
}

t, err := hap.NewTransport(device)
if err != nil {
    return err
}

sess, err := hap.Verify(t, pd) // encrypted session
if err != nil {
    return err
}

err = sess.SetOn(true)
err = sess.SetBrightness(80)  // 0–100
err = sess.SetSaturation(100) // 0–100
err = sess.SetHue(120)        // 0–360°
```

### Reading and other characteristics

The `Set*` helpers are conveniences for the standard HomeKit **Lightbulb** characteristics.
For anything else, use the raw accessors with the appropriate HAP value encoding:

```go
raw, err := sess.ReadCharacteristic(hap.CharBrightness) // → 0x50 0x00 0x00 0x00
err = sess.WriteCharacteristic(myCharUUID, value)
```

HAP value formats are little-endian: `bool` is one byte (`0x00`/`0x01`), `int` is a 32-bit
LE integer, `float` is a 32-bit LE IEEE-754 value. The `Set*` helpers apply these for you.
