# tofn: a cryptography library in Rust

Tofn provides the following:

* An implementation of ECDSA SECP256k1 signing scheme.
* An implementation of ED25519 signing scheme.

tofn is primarily used as part of [tofnd](https://github.com/axelarnetwork/tofnd) for the [Axelar network](https://www.axelar.network). For an older version of the library that included a threshold ECDSA implementation, see the section below on Threshold cryptography.

## Setup

* Get the latest version of Rust stable.
* Clone this repo.
* Run `cargo build` to build the library.
* Run `cargo test` to run the tests.
* Run `GOLDIE_UPDATE=1 cargo test` to generate golden files for relevant tests.

## Threshold cryptography

For an implementation of the [GG20](https://eprint.iacr.org/2020/540.pdf) threshold-ECDSA protocol,
see this version of [tofn](https://github.com/axelarnetwork/tofn/tree/0b441ed758ebed6726f7a2cf1ccce6a95c33152c). This GG20 protocol implementation should not be considered ready for production since it has *known vulnerabilities* against [recently discovered attacks](https://www.verichains.io/tsshock/) on the protocol implementation. This was removed from `tofn` as it is not being used in the Axelar protocol.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
