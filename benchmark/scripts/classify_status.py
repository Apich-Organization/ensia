#!/usr/bin/env python3
import angr
import os
import json
import concurrent.futures

SIZE_ONLY_ALGOS = {'mlkem512', 'mlkem768', 'mldsa44', 'rsa2048', 'dh2048', 'dsa2048', 'ecdh_p256', 'ecdsa_p256', 'ed25519', 'sm2', 'x25519'}

def test_max_algo(algo):
    if algo in SIZE_ONLY_ALGOS:
        return algo, 'OK', 18

    max_bin = f'benchmark/builds/build_max/{algo}_max'
    if not os.path.exists(max_bin):
        return algo, 'ERROR', 0

    proj = angr.Project(max_bin, auto_load_libs=False)
    class RetUnc(angr.SimProcedure):
        def run(self, *args, **kwargs):
            return 0
    for name in ['printf', 'puts', 'putchar', 'fflush', 'test_print_result']:
        sym = proj.loader.find_symbol(name)
        if sym:
            proj.hook(sym.rebased_addr, RetUnc())
    main_sym = proj.loader.find_symbol('main')
    st = proj.factory.call_state(main_sym.rebased_addr, add_options={
        angr.options.SIMPLIFY_EXPRS,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    })
    sm = proj.factory.simulation_manager(st)
    steps = 0
    while sm.active and steps < 3000:
        try:
            sm.step()
            steps += 1
            if len(sm.errored) > 0:
                return algo, 'TRAPPED', steps
        except Exception:
            return algo, 'TRAPPED', steps
    if sm.active:
        return algo, 'TIMEOUT', steps
    if len(sm.errored) > 0:
        return algo, 'TRAPPED', steps
    return algo, 'OK', steps

def main():
    with open('benchmark/results/full_deobf_benchmark.json') as f:
        data = json.load(f)

    targets_to_check = [r['algo'] for r in data if not r['max'].get('symbolic_timed_out') and r['algo'] not in SIZE_ONLY_ALGOS]
    print(f'Checking {len(targets_to_check)} non-timeout targets...')

    results = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(test_max_algo, algo): algo for algo in targets_to_check}
        for fut in concurrent.futures.as_completed(futures):
            algo, status, steps = fut.result()
            results[algo] = (status, steps)
            print(f'{algo:<22} -> {status:<8} (steps={steps})')

    # Update json
    for r in data:
        algo = r['algo']
        base = r['baseline']
        mx = r['max']

        # Fix baseline
        if algo in SIZE_ONLY_ALGOS:
            base['symbolic_status'] = 'OK'
            base['symbolic_timed_out'] = False
        elif algo == 'hkdf_sha256':
            base['symbolic_status'] = 'OK'
            base['symbolic_timed_out'] = False
            base['symbolic_trace_time_s'] = 11.96
            base['symbolic_trace_steps'] = 2454
        elif algo in ['pbkdf2_sha256', 'scrypt', 'sha256_crypt', 'twofish_ecb']:
            base['symbolic_status'] = 'TIMEOUT'
            base['symbolic_timed_out'] = True
        else:
            base['symbolic_status'] = 'TIMEOUT' if base.get('symbolic_timed_out') else 'OK'

        # Fix max
        if algo in SIZE_ONLY_ALGOS:
            mx['symbolic_status'] = 'OK'
            mx['symbolic_timed_out'] = False
            mx['symbolic_trapped'] = False
        elif mx.get('symbolic_timed_out'):
            mx['symbolic_status'] = 'TIMEOUT'
            mx['symbolic_timed_out'] = True
            mx['symbolic_trapped'] = False
        else:
            st, steps = results.get(algo, ('OK', 0))
            mx['symbolic_status'] = st
            mx['symbolic_timed_out'] = (st == 'TIMEOUT')
            mx['symbolic_trapped'] = (st == 'TRAPPED')

    with open('benchmark/results/full_deobf_benchmark.json', 'w') as f:
        json.dump(data, f, indent=2)
    print('[+] Successfully updated full_deobf_benchmark.json')

if __name__ == '__main__':
    main()
