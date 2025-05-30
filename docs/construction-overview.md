# Bitcoin - Axelar Integration: Construction Overview

## Overview
This document describes how Bitcoin is integrated into the Axelar network to
enable seamless cross-chain communication and asset transfers. In summary,
the integration allows general message parsing from Bitcoin to other Axelar-supported
chains, secure cross-chain BTC transfers (wrap/unwrap of BTC), and BTC withdrawals back
to the Bitcoin network.

The Bitcoin tools and mechanisms utilized for this integration are:
* **_OP_RETURN_**: Opcode used to embed metadata (destination chain, contract address, hashed
payload) in Bitcoin transactions to signal messages for cross-chain routing.
* **Multisig (M-of-N threshold signatures)**: Used to control Axelar’s BTC funds on Bitcoin. Only
a threshold of Axelar Verifiers can spend funds.
* **TRUC Transactions**: Recently added V3 Bitcoin transactions used throughout the construction that
eliminate [transaction pinning](https://bitcoinops.org/en/topics/transaction-pinning)
problems.
* **CPFP / Ephemeral Anchors / 1P1C**: The combination of these mechanisms allows
Axelar's Multisig Prover to create Bitcoin transactions without directly paying transaction fees.
The responsibility of paying the necessary transaction fees and ensuring the transactions
are included in Bitcoin is delegated to the relayer. The mechanisms include:
    - **Child Pays for Parent (CPFP)**: A child transaction can be created to pay the
    fee of a parent transaction.
    - **1 Parent 1 Child (1P1C)**: Recently added mechanism that allows a parent transaction that
    is below the minimum feerate, and would normally get rejected, to enter the mempool as a package
    with a child transaction, as long as their combined feerate is sufficient.
    - **Pay To Anchor**: An anchor is a transaction output that
    is added solely to allow a child transaction to CPFP, effectively paying its fees. Pay To Anchor
    (P2A) is a new output script type which efficiently (and cheaply) allows anyone to spend the anchor.
    - **Ephemeral Dust**: Ephemeral dust is a new concept that allows a single dust output
    in a transaction, provided the transaction is zero fee. This type of transaction should be
    created in a 1P1C package where the dust is both created (by the parent) and spent (by the child)
    simultaneously.

## General Message Passing from Bitcoin
When a user wants to send a general message from Bitcoin to another chain via Axelar,
he embeds the message data in a Bitcoin transaction that Axelar can recognize and route.
The end-to-end process from a Bitcoin transaction to a message delivered on a destination chain
is outlined below:

* **Deposit Transaction**: The user creates a Bitcoin transaction with an _OP_RETURN_ output
containing the necessary data for Axelar to route the message.
The data includes the destination chain, destination address
(of the destination smart contract), and the payload (to call the destination smart contract with,
in the GMP case). The opcode can carry up to 80 bytes of data. Given this limitation,
the arbitrary payload must be hashed to fit alongside the destination address and destination
chain within the _OP_RETURN_ data field. To retrieve the original payload, a query would
need to be made to some external data availability service.
Optionally, if the user intends to transfer BTC (not just send a message), the deposit transaction
must include an additional output sending the desired BTC amount to
the multisig address controlled by the Axelar verifiers.
This output effectively locks BTC under Axelar’s control, allowing Axelar to mint
the corresponding wrapped BTC on the destination chain.
<span style="color:red">
The user can find the latest multisig address on the Axelar network or
by looking at the latest main transaction on the Bitcoin network
(see **The Main UTXO** below).
</span>

* **Relay**: The relayer continuously scans Bitcoin for new user deposit transactions
that are confirmed in his view. A transaction is considered confirmed once it reaches
a certain depth in the block tree (i.e., receives k confirmations, where k is the confirmation parameter).
This ensures that the transaction is sufficiently immutable on Bitcoin.
Once confirmed, the relayer broadcasts the transaction to the Axelar network
by calling the `VerifyMessages` function on the Bitcoin Gateway contract.
Deposits are stored on the Gateway contract and will also be useful when withdrawing BTC back
on Bitcoin.

* **Verification**: Once `VerifyMessages` is called, the Voting Verifier contract
initiates a poll. During this poll, the Axelar verifiers independently
check their own Bitcoin full nodes for the deposit transaction and
vote on the validity of the transaction.
Yes means that the deposit was found and is valid, whereas no means that it is not.
If a threshold of verifiers attest to the deposit’s validity,
it is considered verified.

* **Message Routing**: Once a deposit is verified, the relayer calls the `RouteMessages` function
on the Bitcoin Gateway contract, and the message is routed to the appropriate destination chain.

## BTC Withdrawals Back to Bitcoin
BTC withdrawals refer to the process of users redeeming wrapped BTC
on an Axelar-connected chain in order to receive actual Bitcoin on
the Bitcoin network.

Before getting into the withdrawal flow, we must first explain a helpful mechanism that will
be used shortly after:

* **Confirmations Tracking**: It is important for the Prover contract to know whether some
transactions are confirmed or pending in Bitcoin (their status). Confirmed transactions are
transactions that are buried k blocks deep in the Bitcoin chain, while pending transactions are
those that have not been confirmed yet.
For the Prover contract to gain this information, the relayer (or anyone)
can call the `UpdateTxStatus` function on the Bitcoin Gateway contract to prompt the verifiers
to poll the status of specific Bitcoin transactions. The verifiers check their own Bitcoin full nodes
for the transactions and vote on their status. Yes means that the transaction is confirmed,
and no means that it is pending. If a threshold of verifiers attest that a transaction is confirmed,
it is considered confirmed, otherwise it is considered pending.
The Axelar Gateway contract maintains a list of transactions of interest
and their status. If `UpdateTxStatus` is called for a transaction of no interest,
no action is taken.

Now we can proceed with the withdrawal flow:

* **Withdrawal Request**: The Axelar Router contract calls the `RouteMessages` function
on the Bitcoin Gateway contract when there are BTC withdrawal requests from other chains.
These withdrawal requests are stored in the Bitcoin Gateway contract for later processing.

* **The Main UTXO**: On Bitcoin, a persistent main UTXO is maintained.
This output is controlled by the verifier multisig and is the cornerstone
of Axelar's Bitcoin mechanism. It is used to fullfil withdrawal requests
and is where all deposits are eventually consolidated. It is critical that
this UTXO always has enough liquidity to facilitate withdrawals (if not, an automatic
consolidation may be triggered; see **Consolidation Process** below).
When the Prover contract is first deployed, it is initialized with the initial
main UTXO, a small but non-dust output controlled by the verifier multisig.
All transactions spending the main UTXO thereafter are called main transactions,
and their change output is considered the new main UTXO.
The main transactions are considered transactions of interest and their confirmation status
is kept track by the Gateway contract. The relayer makes sure to call `UpdateTxStatus`
in order to update the confirmation status of main transactions when needed.

* **Constructing Main Transactions**: The relayer (or anyone) can call the `ConstructProof` function
on the Bitcoin Gateway contract to construct a new main transaction that pays out
withdrawal requests on Bitcoin. The function call is forwarded to the Prover contract,
where the construction process takes place. The key aspects of this mechanism are:
  - **Precondition**: In order for a new main transaction to be constructed, no more than k main
  transactions must be currently pending. Additionally, there must be accumulated withdrawal requests
  that have not been paid out by previous main transactions.
  - **Main Transaction Inputs**:
    - The previous main UTXO, controlled by the verifier multisig (needs a threshold of verifier signatures).
    - Optionally, a UTXO of consolidated user deposits if available. The goal of this input
    is to provide extra liquidity to the main UTXO. This is input is also controlled by the verifier multisig
    (needs a threshold of verifier signatures). See **Consolidation Process** below.
  - **Main Transaction Outputs**:
    - The new main UTXO, returning any remaining change back to the verifier multisig.
    Note that the transaction includes zero fees, so the entire remaining change amount is returned
    to the new main UTXO.
    - An ephemeral anchor output to be used by the relayer to pay the transaction fees.
    - Multiple outputs paying out withdrawal requests to users. These withdrawal requests
    are the ones accumulated since the last main transaction was constructed.
     (In cases of high traffic, withdrawals are not directly paid to users in the main transaction; see **High Traffic** below.)

* **Signing and Relaying**: After the main transaction is constructed, it is signed by the verifiers.
Since the main transaction is zero fee, it is the responsibility of the relayer (or anyone else)
thereafter to ensure that the main transaction is included
in Bitcoin. Subsequently, the relayer attaches a child transaction of his own to the
ephemeral anchor output of the main transaction, paying the necessary fees for both transactions
to be included as a 1P1C package.

## Consolidation Process
Over time, user deposits will accumulate on Bitcoin and need to be merged into
the main UTXO. This is important to ensure sufficient liquidity of the main UTXO in order
to facilitate withdrawals. Note that all withdrawals are paid out from respective deposits that
are eventually merged into the main UTXO.
The consolidation process periodically consolidates these deposits into a single large UTXO
in order to easily merge it into the main UTXO.
Consolidation is triggered by the relayer (or anyone) calling the `Consolidate` function
on the Bitcoin Gateway contract.

Key points of the consolidation mechanism:

* **Trigger Conditions**: The consolidation process proceeds only when certain criteria are met
– for example, after a set number of deposits are accumulated, or when the total value in loose deposit UTXOs exceeds a
threshold, or simply on a timed schedule.

* **Consolidation Transaction**: A consolidation transaction merges loose UTXOs into a single
large UTXO. A consolidation transaction gathers multiple loose outputs as inputs, and produces
a consolidated output (sent back to the multisig) that combines their value, along with an ephemeral
anchor output to be used by the relayer to pay the transaction fees. These transactions are TRUC
and have a 10,000 vB size limit. Additionally, its inputs are all spendable by the multisig,
requiring many signatures in order to be unlocked, making them large in size.
This means that only a limited number of inputs can be consolidated into a single consolidation
transaction.

* **Recursive Merging and Grouping**: If there are too many inputs to fit into one transaction,
consolidation happens in stages.
UTXOs requiring consolidation are grouped into several intermediate consolidation transactions
in order to fit size limits. Each consolidation transaction yields a single output of the combined value
of its inputs.
Those outputs can further be merged in subsequent rounds in a tree-like structure. This recursive
approach ensures that ultimately all UTXOs will be merged into a single large UTXO.

* **Consolidation Process**: When the `Consolidate` function is called, after the trigger conditions
are checked, the consolidation process takes place. The UTXOs that get consolidated into one large UTXO
are all the unspent deposit outputs (known by the Gateway contract) and the previous single
consolidated output if it is not spent yet by a main transaction. All consolidation transactions are
constructed at once and prompted to be signed by the verifiers.
Thereafter, the relayer (or anyone) makes sure that all consolidation transactions are included in Bitcoin.

* **Relaying and Mempool Inclusion**: The consolidation transactions may form a tree structure and have child/parent relationships
with each other. Due to Bitcoin's mempool inclusion rules, this means that consolidation transactions
of different depths (in the tree) cannot be in the mempool at the same time.
To be precise, first, only the transactions of the first level will be included in the mempool
and all other levels will be dropped. After the first level is included in a block, the relayer must
rebroadcast the second level transactions, which at this point will be included in the mempool and
eventually included in a block. This process is repeated for each level until all consolidation
transactions are included in a block.
Consolidation transactions are considered transactions of interest and their confirmation status
is kept track by the Gateway contract. The relayer makes sure to call `UpdateTxStatus`
in order to update the confirmation status of consolidation transactions when needed.

* **Merging with the Main UTXO**: When it is time to create a new main transaction, after
`ConstructProof` is called, the Prover contract checks if there exists a confirmed unspent
consolidated large UTXO (asking the Gateway contract). If there is, it is provided as input
to the main transaction being constructed.

## Special Cases

### High Traffic
The main transaction is a TRUC transaction with a 10,000 vB size limit.
If a large number of withdrawals are requested at the same time, the main transaction may not be able
to fit enough outputs to pay out all of them. Here is how to handle this case:

* **Helper Outputs**: When the main transaction is constructed it is checked whether there are enough
outputs to pay out all withdrawal requests. If not, instead of including direct withdrawal outputs
in the main transaction, some helper outputs spendable by the verifier multisig are included instead.
The purpose of these helper outputs is to be spent by extra helper transactions
that they pay out the withdrawal requests to end users instead.
The helper outputs are provided exactly the required liquidity in order for the helper transactions
to pay out the withdrawal requests. The rest of the liquidity goes to the new main UTXO similar to
the normal case.

* **Helper Transactions**: At the same time, the helper transactions are also constructed (one
for each helper output). Here is their interface:
  - **Inputs**: The only input of a helper transaction is the corresponding helper output.
  - **Outputs**:
    - Multiple outputs paying out withdrawal requests to end users.
    - An anchor output to be used by the relayer to pay the transaction fees.
A helper transaction spends the entire input amount provided by the helper output
to pay withdrawals and leaves no change.

* **Relaying and Mempool Inclusion**: Once the main transaction and helper transactions are constructed and
signed, the relayer (or anyone) makes sure that all of them are included in Bitcoin.
Note that the helper transactions are children of the main transaction. Due to the mempool inclusion policy
of TRUC transactions, the helper transactions will be included in the mempool after the main transaction
is included in a block. Hence,

* **Latency and Throughput**: Because of the mempool inclusion policy described above, in situations of high withdrawal
demand, where helper transactions are necessary, the latency of withdrawal processing increases by one block time.
<span style="color:red">
The maximum theoretical throughput of the system is *TODO*.
</span>

### Insufficient Liquidity
In some edge cases (e.g. all wrapped BTC holders are requesting withdraw), the main UTXO may not have
enough liquidity to pay out all withdrawal requests.
This means that the main UTXO and the confirmed consolidated UTXO (if available) cannot cover the full withdrawal amount.
In this case, an automatic consolidation is triggered to supply the necessary liquidity to the main UTXO.

* **Trigger Conditions**: When the `ConstructProof` function is called, after the necessary checks are complete,
and it is decided that a main transaction must be created, an additional check is made:
If the sum of the main UTXO amount and the confirmed consolidated UTXO amount (if it exists) is not enough
to pay out all withdrawal requests, an automatic consolidation is triggered. If it is enough, the main transaction
is constructed as normal.

* **Automatic Consolidation**: The automatic consolidation is similar to the consolidation process described
in the **Consolidation Process** section above. All the unspent deposit outputs, and the previous single
consolidated large UTXO (if it is not spent yet by a main transaction) are consolidated into a new single large UTXO.
After all the necessary consolidation transactions are constructed, the new main transaction is constructed, spending the
newly created consolidated UTXO in addition to the previous main UTXO. This will ensure that there is now enough liquidity
to pay out all withdrawal requests.

* **Relaying and Mempool Inclusion**: All the consolidation transactions, and the main transaction
are signed by the verifiers, and the relayer makes sure that all of them are included in Bitcoin.
Because of the mempool inclusion policy described in previous sections, the main transaction will be
included in the mempool after all the consolidation transactions are included in blocks.
Hence, at times of extremely high withdrawal demand and low liquidity, the latency of withdrawal processing increases
by a few block times (realistically, no more than 2-3 blocks).

### Combination of High Traffic and Insufficient Liquidity
The above two techniques can be combined in cases of both high traffic and insufficient liquidity.