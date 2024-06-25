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
- Open a new terminal and navigate to the directory where this repo was cloned before.
- `cargo run <path to .bitcoin directory>`. Example paths:
  * Ubuntu: `/home/<username>/snap/bitcoin-core/common/.bitcoin/`
  * MacOS: `/home/<username>/.bitcoin/`
- The peg-in and peg-out transactions, along with a block that includes them, are printed.

## Acknowledgements
- The Bitcoin Script used for this demo is inspired by: https://gist.github.com/mappum/da11e37f4e90891642a52621594d03f6
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) was used to construct and sign Bitcoin transactions.
- [rust-bitcoincore-rpc](https://github.com/rust-bitcoin/rust-bitcoincore-rpc) was used to communicate with the local Bitcoin regtest RPC.
