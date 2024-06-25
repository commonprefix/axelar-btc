# Build as many maximal-sized handover_txs as needed
# to bring down the number of locking outputs to max_output_no
def handover(old_outputs, max_output_no, max_tx_size, weighted_multisig_with_new_keys):
    # fan_in: number of old outputs per new output
    # Each handover tx has at most `fan_in` inputs per output
    # `fan_in == 1` if `len(old_outputs) < max_output_no`
    fan_in = max(1, len(old_outputs)//max_output_no))

    # Assume that all inputs & outputs have the same size
    # This assumption might be wrong for inputs if the number of validator sigs varies
    # Let there be a data structure from which we draw `suitable_old_validator_sigs`
    model_input = spend(old_outputs[0], suitable_old_validator_sigs)
    model_output = {
        'value': 0,
        'script': p2tr(key = None, script = weighted_multisig_with_new_keys)
    }
    max_outputs_per_tx = max_tx_size // (fan_in*model_input.size() + model_output.size())

    handover_txs = []
    # TODO: reorder `old_outputs` to aim for a similar value across new outputs?
    while len(old_outputs) > 0:
        handover_txs.append(Tx())
        for _ in range(max_outputs_per_tx):
            in_value = 0
            for _ in range(0, fan_in):
                if len(old_outputs) == 0: break
                old_output = old_outputs.pop()
                in_value += old_output['value']
                handover_txs[-1].add_input(spend(old_output['script'], suitable_old_validator_sigs))
            handover_txs[-1].add_output({
                'value': in_value,
                'script': p2tr(key = None, script = weighted_multisig_with_new_keys)
            })
            if len(old_outputs) == 0: break

    return handover_txs

# `net_payout` is the payment to the client after extracting our fee
# TODO: miner_fee should be per vbyte
def peg_out(net_payout, old_outputs, peg_out_pk, miner_fee, dust_limit):
    input_value = net_payout + miner_fee
    outputs = [{
        'value': net_payout,
        'script': p2tr(key = peg_out_pk, script = None)
    }]

    filtered_old_outputs = [x for x in old_outputs
        if x['value'] == input_value or x['value'] >= input_value + dust_limit]

    if filtered_old_outputs: # there's at least one old_output with ['value'] >= input_value
        best_val = max_amount
        for old_output in filtered_old_outputs:
            if old_output['value'] < best_val:
                best_val = old_output['value']
                best_old_output = old_output

            if best_val != input_value: # we need a change output
                outputs.append({
                    'value': best_old_output['value'] - input_value,
                    'script': old_output_to_spend['script']
                })
            return Tx(inputs = [best_old_output], outputs = outputs, sigs=suitable_validator_sigs)

    # add old_outputs until net_payout is reached
    acc = 0
    old_outputs_to_spend = []
    # TODO: reorder `old_outputs` to reduce number of inputs/hit the exact input_value?
    for old_output in old_outputs:
        acc += old_output['value']
        old_outputs_to_spend.append(old_output)
        if acc == input_value or acc >= input_value + dust_limit: break
    if acc < input_value: # all old outputs can't match input_value, bug!
        raise Halt_and_catch_fire

    if acc != input_value: # we need a change output
        outputs.append({
            'value': acc - input_value,
            'script': old_outputs_to_spend[0]['script']
        })
    return Tx(inputs = old_outputs_to_spend, outputs = outputs, sigs = suitable_validator_sigs)
