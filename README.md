# Peg-in & Peg-out Transactions Demo

We provide an example of the peg-in transaction, by which a user moves its
coins to the Axelar validators' output, along with an example of the peg-out
transaction, with which the Axelar validators unlock previously pegged-in
BTC. These transactions are valid and would be accepted by the Bitcoin
network. To verify this, they are passed to a running Bitcoin Core daemon set to
a local (`regtest`) network and tested for acceptance by its mempool.

## Setup
- Install Bitcoin Core:
  * Ubuntu: `snap install bitcoin-core` (If it requires other packages, install them first with `apt`.)
  * MacOS: follow the instructions found at [https://bitcoin.org/en/full-node#osx-daemon](https://bitcoin.org/en/full-node#osx-daemon).
- From a terminal, clone this repo: `git clone git@github.com:commonprefix/axelar-btc.git`.

## Execution
- Start a Bitcoin Core daemon:
  * Ubuntu: `bitcoin-core.daemon -chain=regtest`
  * MacOS: `bitcoind -daemon -chain=regtest`
- Copy the directory where your `.cookie` is stored:
  * Ubuntu: `/home/<username>/snap/bitcoin-core/common/.bitcoin/regtest/`
  * MacOS: `/home/<username>/.bitcoin/regtest/`
- Open a new terminal and navigate to the directory where this repo was cloned before.
- Replace the path in the string of line 21 of`src/main.rs` with the previously copied `.cookie` directory and save the file.
- `cargo run`
- The peg-in and peg-out transactions, along with a block that includes them, are printed.

## References
The script is inspired by: https://gist.github.com/mappum/da11e37f4e90891642a52621594d03f6
