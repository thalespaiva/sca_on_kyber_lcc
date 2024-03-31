#!/usr/bin/python3

import subprocess
import os
import sys
import tempfile
import time

import numpy as np

import solver


def generate_inequalities(tmpdirname, seed, n_total_inequalities, confusion_matrix):
    os.mkdir(os.path.join(tmpdirname, 'inequalities'))

    generate_inequalities_cmd_line = [
        os.path.abspath('../kyber_sca_simulation/build/kyber_sca_generate_inequalities'),
        seed,
        n_total_inequalities,
        confusion_matrix,
    ]

    subprocess.run(generate_inequalities_cmd_line, cwd=tmpdirname)

# Parameters for Kyber768
KYBER_N = 256
KYBER_K = 3
KYBER_ETA1 = 2
N_UNKNOWNS = KYBER_N * KYBER_K * 2

# This helps in avoiding useless costly iterations that won't change much the final result
CIPHERTEXT_ERROR_MARGIN = 10

def get_total_number_of_inequalities(inequalities_data):
    full_a, full_b, full_is_geq_zero, full_number_of_ciphertexts, solution = inequalities_data
    return full_a.shape[0]

def find_number_of_ciphertexts_needed(inequalities_data, report_info):
    left = 0

    right = get_total_number_of_inequalities(inequalities_data)

    min_approx_n_ciphertexts_success = np.inf
    while (left < right):
        mid = (left + right) // 2
        found_solution, approx_n_ciphertexts = try_to_solve(inequalities_data, mid, report_info)

        if found_solution:
            min_approx_n_ciphertexts_success = min(min_approx_n_ciphertexts_success, approx_n_ciphertexts)
        else:
            if (abs(min_approx_n_ciphertexts_success - approx_n_ciphertexts) <= CIPHERTEXT_ERROR_MARGIN):
                break

        if found_solution:
            right = mid
        else:
            left = mid + 1
    return right

def read_inequalities_from_directory(dirpath):
    import os

    a = np.loadtxt(os.path.join(dirpath, 'a.dat'),
               delimiter=',', usecols=range(N_UNKNOWNS), dtype=np.int16)

    b = np.loadtxt(os.path.join(dirpath, 'b.dat'),
                   delimiter=',', usecols=range(a.shape[0]), dtype=np.int16)

    is_geq_zero = np.loadtxt(os.path.join(dirpath, 'is_geq_zero.dat'),
                             delimiter=',', usecols=range(a.shape[0]), dtype=np.int16)


    solution = np.loadtxt(os.path.join(dirpath, 'solution.dat'),
                         delimiter=',', usecols=range(a.shape[1]), dtype=np.int16)

    full_number_of_ciphertexts = np.loadtxt(os.path.join(dirpath, 'number_of_ciphertexts.dat'),
                                            delimiter=',', dtype=np.int32)

    return a, b, is_geq_zero, full_number_of_ciphertexts, solution


def try_to_solve(inequalities_data, n_inequalities_to_use, report_info):

    full_a, full_b, full_is_geq_zero, full_number_of_ciphertexts, solution = inequalities_data

    a = full_a[:n_inequalities_to_use]
    b = full_b[:n_inequalities_to_use]
    is_geq_zero = full_is_geq_zero[:n_inequalities_to_use]

    time_start = time.time()

    guess, found_solution, fraction_of_solution_recovered, n_iterations = (
        solver.solve_inequalities(KYBER_ETA1, a, b, is_geq_zero, solution=solution))

    time_end = time.time()

    approx_n_ciphertexts = (n_inequalities_to_use / full_a.shape[0] * full_number_of_ciphertexts)

    print('Belief Propagation', end=',')
    print(f'{report_info["seed"]}', end=',')
    print(a.shape[0], end=',')
    print(found_solution, end=',')
    print('%.2lf' % fraction_of_solution_recovered, end=',')
    print(n_iterations, end=',')
    print('%.2lf' % (time_end - time_start), end=',')
    print('%.2lf' % approx_n_ciphertexts, end=',')
    print(f'{report_info["confusion_matrix"]}', end='')
    print()

    sys.stdout.flush()

    return found_solution, approx_n_ciphertexts

def print_header():
    print("algorithm,", end='')
    print("seed,", end='')
    print("n_inequalities,", end='')
    print("recovered_key,", end='')
    print("fraction_of_solution_recovered,", end='')
    print("n_iterations,", end='')
    print("time_seconds_solve_inequalities,", end='')
    print("approx_number_of_ciphertexts,", end='')
    print("confusion_matrix", end='')
    print()

if __name__ == '__main__':

    if len(sys.argv) != 4:
        print(f'Usage {sys.argv[0]} seed n_total_inequalities confusion_matrix')
        sys.exit(1)

    seed = sys.argv[1]
    n_total_inequalities = sys.argv[2]
    confusion_matrix = sys.argv[3]

    print_header()

    report_info = {
        'seed': seed,
        'confusion_matrix': confusion_matrix,
    }
    with tempfile.TemporaryDirectory() as tmpdirname:
        generate_inequalities(tmpdirname, seed, n_total_inequalities, os.path.abspath(confusion_matrix))

        inequalities_data = read_inequalities_from_directory(os.path.join(tmpdirname, 'inequalities'))
        find_number_of_ciphertexts_needed(inequalities_data, report_info)
