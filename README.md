# Tofn (t-of-n): a threshold cryptography library in Rust

Tofn provides the following:

* An implementation of ECDSA SECP256k1 signing scheme.
* An implementation of ED25519 signing scheme.

* A general-purpose SDK (software development kit) to facilitate the development and use of threshold cryptography protocols such as GG20.

## Setup

* Get the latest version of Rust stable.
* Clone this repo.
* Run `cargo build --release` to build the library.
* Run `cargo test --release` to run the tests.

## Threshold cryptography

For an implementation of the [GG20](https://eprint.iacr.org/2020/540.pdf) threshold-ECDSA protocol,
see this version (with *known vulnerabilities*) of [tofn](https://github.com/axelarnetwork/tofn/tree/0b441ed758ebed6726f7a2cf1ccce6a95c33152c). The GG20 protocol implementation should not be considered ready for production since it doesn't protect against [recently discovered attacks](https://www.verichains.io/tsshock/) on the protocol implementation. This was removed from `tofn` as it is not being used in the Axelar protocol.

## Security notes

* In our security model, we don't guarantee security if the attacker has access to the device.

## Message ordering

* We assume that an honest party's Round x message is sent before Round x + i.
* We also assume that no party receives a Round x + i message from any other party before their Round x message.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
