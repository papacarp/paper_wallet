
# Decred Paper Wallet Concept Validation

This collection of scripts is a proof of concept for a client side javascript only paper wallet implementation.  The goal of this code currently is to put the math together to properly calculate child keys in a way that matches exactly the current [hdkeychain.go](https://github.com/decred/dcrd/blob/master/hdkeychain/extendedkey.go)
implementation in dcrd.

It is expected that this repository will evolve into a full implementation of a paper wallet generator with a current target to use the [bitaddress](https://www.bitaddress.org) paper wallet implementation as a guide.

Functionality Required and implemented:

* SHA512
* ECC: secp256k1
* Blake256
* Ripemd160

Check console output for results.
