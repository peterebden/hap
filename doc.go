// Package hap is a controller for the HomeKit Accessory Protocol over Bluetooth LE
// (HAP-BLE). It lets a program act as the controller side of HomeKit: pair with a HAP
// accessory using its 8-digit setup code, re-establish an encrypted session on each
// connection, and read or write the accessory's characteristics - for example to drive a
// HomeKit light bulb's on/off, brightness, hue and saturation.
//
// It is the controller counterpart to server-side libraries such as
// github.com/brutella/hap: that one is an accessory, this one controls one.
//
// # Overview
//
// HomeKit exposes accessory features as GATT characteristics, but HAP wraps every access in
// its own protocol on top of GATT. Using this package mirrors the protocol's shape:
//
//   - [NewTransport] sets up the GATT plumbing over a connected tinygo bluetooth device.
//   - [Pair] runs pair-setup once with the setup code and returns [PairingData] to persist.
//   - [Verify] runs pair-verify from saved PairingData and returns an encrypted [Session].
//   - [Session] reads and writes characteristics; SetOn, SetBrightness, SetHue and
//     SetSaturation are conveniences for the standard Lightbulb characteristics.
//
// # Requirements
//
// The GATT transport uses tinygo.org/x/bluetooth on the Linux/BlueZ backend, and needs
// central-side GATT descriptor reads that upstream tinygo bluetooth does not yet expose;
// see the README for the replace directive required until that change lands.
package hap
