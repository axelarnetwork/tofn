# Tofn (t-of-n): a threshold cryptography library in Rust

Tofn provides the following:
* An implementation of the [GG20](https://eprint.iacr.org/2020/540.pdf) threshold-ECDSA protocol.
* A general-purpose SDK (software development kit) to facilitate the development and use of threshold cryptography protocols such as GG20.

# Setup

* Get the latest version of Rust stable (currently 1.53.0).
* Clone this repo.
* You might need to install the GMP library.  On MacOS:
    ```
    brew install gmp
    ```
On Ubuntu:
    ```
    sudo apt install libgmp-dev
    ```

# Demo and tests

Tofn integration tests (in `tests/integration`) serve to demo use of the library.  (These demos would be in the `examples` directory but we want them to run automatically as part of the normal test sequence.)

Demo test hieararchy:
```
tests
└── integration
    ├── multi_thread
    └── single_thread
        └── malicious
            ├── keygen.rs
            ├── sign.rs
            └── timeout_corrupt.rs
```

## Multi-threaded tests

Tests in `multi_thread` are a more accurate reflection of typical use than those in `single_thread`.

Threshold cryptography protocols are multi-party computation protocols: parties exchange messages with one another and perform local computations in order to reach consensus on an output of the protocol.

The `multi_thread` tests aim to simulate such an environment by spawning an independent thread for each party.  These tests simulate network communication by using concurrency primitives from Rust's standard library (`sync::mpsc`) to pass messages between threads.

Run all multi-threaded integration tests:
```
cargo test --test integration -- multi_thread
```

## Single-threaded tests

Multi-threaded code is inherently more difficult to write, test, and debug.  For development purposes it is useful to have a single-threaded reference implementation so as to eliminate concurrency as a source of bugs.  Most examples of tofn functionality occur in `single_thread`.

Some tests illustrate the fault protection and identification properties of the GG20 protocol.  These tests require one or more parties to act maliciously during protocol execution.  Malicious behaviour is enabled in tofn via the `malicious` crate feature---see [Malicious crate feature](#malicious-crate-feature) below.

Run all single-threaded integration tests with only honest parties:
```
cargo test --test integration -- single_thread
```

Run all single-threaded integration tests, including those with malicious parties:
```
cargo test --all-features --test integration -- single_thread
```
Tests using `malicious` display extensive log messages to the terminal.  For example:
```
Jul 23 10:46:04.933  INFO integration::single_thread::malicious::sign: sign with malicious behaviour R6BadProof
Jul 23 10:46:13.005  INFO tofn::gg20::sign::malicious: malicious peer 3 does R6BadProof
Jul 23 10:46:13.273  WARN tofn::gg20::sign::r7::happy: peer 0 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
Jul 23 10:46:13.312  WARN tofn::gg20::sign::r7::happy: peer 1 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
Jul 23 10:46:13.350  WARN tofn::gg20::sign::r7::happy: peer 2 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
Jul 23 10:46:13.391  WARN tofn::gg20::sign::r7::happy: peer 3 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
Jul 23 10:46:13.429  WARN tofn::gg20::sign::r7::happy: peer 4 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
Jul 23 10:46:13.470  WARN tofn::gg20::sign::r7::happy: peer 5 says: pedersen proof wc failed to verify for peer 3 because ['wc' check fail]
```

# Two types of tofn user

The tofn SDK supports two types of users:
1. Library users
2. Protocol implementers

## Library users

A typical library user should need code from only the following tofn modules:

* `tofn::sdk::api` and `tofn::collections` for generic tofn SDK.
* `tofn::gg20` for protocol-specific code for the GG20 protocol.

See [Demo and tests](#demo-and-tests) for working code to illustrate use of tofn.

See the [Tofnd](https://github.com/axelarnetwork/tofnd) crate for usage of tofn in production code.

The core of the API is a generic `Protocol` type:
```rust
pub enum Protocol<F, K, P> {
    NotDone(Round<F, K, P>),
    Done(ProtocolOutput<F, P>),
}
```
where
* `F` is the type of the final output of the protocol.  (Examples: keygen produces a secret key share, sign produces a signature.)
* `K`, `P` are marker types for typed collection indices.  See [Typed collection indices](#typed-collection-indices) below.

Specific protocol implementations provide constructors that create a new concrete `Protocol` instance.  Examples:
* `tofn::gg20::keygen::new_keygen` returns a new keygen protocol
* `tofn::gg20::sign::new_sign` returns a new sign protocol

Each party in the protocol has its own `Protocol` instance.
A `Protocol` can be either `Done` or `NotDone`.  The `Done` variant has `ProtocolOutput` data defined like so:
```rust
pub type ProtocolOutput<F, P> = Result<F, ProtocolFaulters<P>>;
pub type ProtocolFaulters<P> = FillVecMap<P, Fault>;
```
where the `ProtocolOutput` variants are:
* `Ok(output)`: the protocol completed in happy path, producing `output` of type `F` (eg. secret key share or signature).
* `Err(faulters)`: the protocol completed in sad path.  An output of type `F` could not be produced because one or more parties was malicious.  `faulters` is a list of malicious parties detected by this `Protocol` instance during execution.  `ProtocolFaulters` is a custom collection type describing the faulty parties.

The `NotDone` variant has `Round` data with several core methods used to exchange messages and progress the protocol to the next round:
* `bcast_out`, `p2ps_out`: outgoing messages to be sent over the network to other parties.
* `msg_in`: incoming messages received over the network from other parties.
* `expecting_more_msgs_this_round`: have we received all the incoming messages we expect for this round?  Library users use this method to determine whether it's safe to progress to the next round.
* `execute_next_round`: proceed to the next round of the protocol with whatever messages we have received so far.  Consumes `self` and returns a new `Protocol` instance for the next round.
    * If a message from party `A` is missing then `A` is flagged as a faulter.  This is how tofn facilitates timeout faults.

## Protocol implementers

A typical protocol implementer would use code from the following tofn modules:

* `tofn::sdk::api`
* `tofn::sdk::implementer_api`
* `tofn::collections`

See the `tofn::gg20` module for an example of a protocol built using the tofn SDK.

The intent of the implementer API is to allow the protocol implementer to concentrate only on the stateless math functions for each round that map
```
(current_state, incoming_messages) -> (next_state, outgoing_messages)
```
The implementer does not need to worry about generic work such as collecting incoming messages, deserializing data, identifying generic faults (timeout, message corruption), etc.

Concretely, protocol implementers must supply:
* A constructor for a party in the protocol.  Examples: `gg20::keygen::new_keygen`, `gg20::sign::new_sign`.
* For each round of the protocol: a struct implementing the `Executer` trait from one of the modules `no_messages`, `bcast_only`, `p2p_only`, `bcast_and_p2p` according to which types of messages are expected in this round.

# All messages delivered to all parties

Tofn requires that all messages be delivered to all parties.  Specifically:
* **p2p:** Any p2p message from `A` to `B` should also be delivered to all other parties `C`.
* **self-delivery:** A party `A` treats a missing message from any party `P` the same way, even if `P=A`: party `P` is declared as a faulter.

# Support for multiple shares per party

Tofn protocols may allow one party to have multiple shares in the protocol.  For example, keygen could be invoked with 5 parties having share counts 2,3,6,2,1 for a total of 14 shares.

Protocol implementers need not concern themselves with the distinction between parties and shares.  Indeed, the tofn SDK does not even expose information about parties in the `Executer` trait implemented by each protocol round.

Each `Protocol` instance corresponds to a _share_, not a party.  Rounds that produce outgoing p2p messages must produce one message for each other _share_.

Incoming messages indicate only the _party_ from whom the message is sent and not the individual _share_ controlled by that party.  The tofn SDK automatically bundles metadata into each message so that incoming messages can be routed to the appropriate share.

Protocol implementers identify faulty shares but the tofn API attributes faults only to a _party_, not a share.  The tofn SDK automatically translates share faults provided by the protocol implementer into party faults consumed by tofn users.

# Avoid panic: `TofnResult` is for fatal errors only

Tofn strives to avoid panics.  (Currently most but not all potential panic points have been eliminated from tofn.)

Instead, tofn has a `TofnResult` type reserved only for fatal errors:

```rust
pub type TofnResult<T> = Result<T, TofnFatal>;
pub struct TofnFatal;
```

A library user who encounters a `TofnFatal` should gracefully terminate the protocol according to the context of the specific application.  Any `Protocol` method that returns `TofnFatal` should be viewed as a confession of fault by that party.

Protocol implementers should not return `TofnFatal` when malicious behaviour is detected.  Instead, move the protocol to `Done` state and return a faulters list `Ok(Done(Err(faulters)))` that is processed by the tofn SDK---see `gg20` protocol implementation for details.

# Malicious crate feature

Enabling the `malicious` crate feature allows the user to specify that a given party should behave maliciously at a certain point during the protocol.

## Example

With `malicious` enabled the `new_keygen` function takes an additional argument of type `Behaviour`.

The following code instructs the party to corrupt her commitment to the elliptic curve point `y_i` computed during round 1 of the GG20 keygen protocol:

```rust
new_keygen(
    party_share_counts,
    threshold,
    party_id,
    subshare_id,
    secret_recovery_key,
    session_nonce,
    Behaviour::R1BadCommit,
)
```

# Tofn collection types

The module `tofn::collections` provides several custom collection types such as `VecMap`, `FillVecMap`, `HoleVecMap`, etc.  These collection types are especially useful for threshold cryptography.  They build on the `Vec` collection type from Rust's standard 
library.

TODO: more to come.

## Typed collection indices

The `VecMap` collection type is a wrapper for `Vec` from Rust's standard library except that items in the collection are not indexed by `usize`.  Instead items are indexed by a wrapper type `TypedUsize` defined as follows:

```rust
pub struct TypedUsize<K>(usize, PhantomData<K>);
```
Users create their own marker type like so:
```rust
pub struct SignPartyId;
```
and then specify the index type of the collection:
```rust
let my_vecmap = VecMap<SignPartyId, T>::from_vec(vec![t0, t1, t2]);
```

Several other crates exist for this purpose but none of them has the unique combination of features we desire in tofn.  See the [typed_index_collections](https://docs.rs/typed-index-collections/3.0.3/typed_index_collections/index.html#similar-crates) crate for a list of similar cates.

The purpose of `TypedUsize` is to avoid accidental misuse of indices as a source of bugs.

### Example

Threshold signature schemes consist of two protocols: `keygen` and `sign`.  A group of `6` parties will participate in `keygen` in order to produce secret shares of an ECDSA public key `PK`.  Let us label these parties `0,1,2,3,4,5`.

Later a subset `1,3,5` of those parties participates in `sign` in order to sign a message under `PK`.  These `sign` participants are each assigned a new label for the duration of the `sign` protocol: `0,1,2`.  So each `sign` party label has an associated `keygen` party label: `0->1, 1->3, 2->5`.

Some collection types used in the `sign` implementation index only over `sign` parties, whereas others index over all `keygen` parties.  If both of these index types are `usize` then it is easy to confuse them, creating bugs.  `TypedUsize` allows us to leverage Rust's type system to eliminate index confusion at compile time.

To complicate matters further, tofn supports multiple shares per party.  Each `keygen` protocol specifies both the number of parties in the protocol and the number of shares allocated to each party.

For example, `keygen` could be invoked with 5 parties having share counts `2,3,6,2,1` for a total of 14 shares.  We thus have four distinct index types: keygen parties, keygen shares, sign parties, and sign shares.

# Security notes

* In our security model, we don't guarantee security if the attacker has access to the device.

## Message authenticity and integrity

Protocol messages from other parties are delivered via the `msg_in` API call:
```rust
msg_in(from, bytes)
```
where

* `from` is an identifier for the party `A` from whom the message is received.  (Party identifiers in tofn are implemented as a `usize`.)
* `bytes` is the serialized payload of `A`'s message.

It is assumed that these messages have both _authenticity_ and _integrity_: if party `B` receives a call to `msg_in` containing a message `bytes` from party `A` then that message really did come from `A`, it really was intended for `B`, and the `bytes` are exactly what `A` intended.

As such, if `bytes` is malformed or malicious then `B` will accuse `A` of faulty behaviour.

## Message ordering

* We assume that an honest party's Round x message is sent before Round x + i.
* We also assume that no party receives a Round x + i message from any other party before their Round x message.

# License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.