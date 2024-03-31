#   This file was adapted from the Roulette paper
#   Paper: Jeroen Delvaux,
#   "Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber", CHES 2022,
#   https://eprint.iacr.org/2021/1622
#
#   https://github.com/Crypto-TII/roulette/blob/main/source/solver.py
#

import numpy as np
from scipy.stats import binom, norm
import time
import sys

def error_print(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)

def evaluate_inequalities_fast(a, b, solution):
        return (np.matmul(a, solution) + b) >= 0

def solve_inequalities(kyber_eta1, a, b, is_geq_zero,
                       max_nb_of_iterations=16,
                       verbose=True,
                       solution=None): # analyze convergence rate with a known solution
    if verbose:
        error_print("Solving inequalities...")
    eta = kyber_eta1
    [nb_of_inequalities, nb_of_unknowns] = a.shape
    guess = np.zeros((nb_of_unknowns), dtype=int)
    if verbose and solution is not None:
        nb_correct = np.count_nonzero(solution == guess)
        error_print("Number of correctly guessed unknowns: {:d}/{:d}"
                .format(nb_correct, len(solution)))
    if nb_of_inequalities == 0:
        return guess
    nb_of_values = 2*eta + 1
    x = np.arange(-eta, eta+1, dtype=np.int8)
    x_pmf = binom.pmf(x + eta, 2*eta, 0.5)
    x_pmf = np.repeat(x_pmf.reshape(1,-1), nb_of_unknowns, axis=0)
    a = a.astype(np.int16)
    a_squared = np.square(a)
    prob_geq_zero = np.zeros((nb_of_inequalities), dtype=float)
    p_failure_is_observed = np.count_nonzero(is_geq_zero) / nb_of_inequalities
    mean = np.matmul(x_pmf, x)
    variance = np.matmul(x_pmf, np.square(x)) - np.square(mean)
    mean = np.matmul(a, mean)
    variance = np.matmul(a_squared, variance)
    zscore = np.divide(mean + 0.5 + b, np.sqrt(variance))
    p_failure_is_reality = norm.cdf(zscore) # central limit theorem
    p_failure_is_reality = np.mean(p_failure_is_reality)
    p_inequality_is_correct = min(
            p_failure_is_reality / p_failure_is_observed, 1.0)
    prob_geq_zero[is_geq_zero] = p_inequality_is_correct
    fitness = np.zeros((max_nb_of_iterations), dtype=float)
    fitness_max = np.sum(np.maximum(prob_geq_zero, 1 - prob_geq_zero))

    total_iterations = 0
    for z in range(max_nb_of_iterations):
        if verbose:
            error_print("Iteration " + str(z))
            time_start = time.time()
        mean = np.matmul(x_pmf, x)
        variance = np.matmul(x_pmf, np.square(x)) - np.square(mean)
        mean = np.multiply(a, np.repeat(mean[np.newaxis,:],
                nb_of_inequalities, axis=0))
        variance = np.multiply(
            a_squared,
            np.repeat(variance[np.newaxis,:], nb_of_inequalities, axis=0))
        mean = mean.sum(axis=1).reshape(-1,1).repeat(nb_of_unknowns, axis=1) \
                - mean
        mean += b[:, np.newaxis]
        variance = variance.sum(axis=1).reshape(-1,1).repeat(nb_of_unknowns,
                axis=1) - variance
        variance = np.clip(variance, 1, None)
        psuccess = np.zeros((nb_of_values, nb_of_inequalities,
                nb_of_unknowns), dtype=float)
        for j in range(nb_of_values):
            zscore = np.divide(a*x[j] + mean + 0.5, np.sqrt(variance))
            psuccess[j,:,:] = norm.cdf(zscore) # central limit theorem
        psuccess = np.transpose(psuccess, axes=[2,0,1])
        psuccess = \
            np.multiply(psuccess, prob_geq_zero[np.newaxis,np.newaxis,:]) + \
            np.multiply(1-psuccess, 1-prob_geq_zero[np.newaxis,np.newaxis,:])
        psuccess = np.clip(psuccess, 10e-5, None)
        psuccess = np.sum(np.log(psuccess), axis=2)
        row_means = psuccess.max(axis=1)
        psuccess -= row_means[:, np.newaxis]
        psuccess = np.exp(psuccess)
        x_pmf = np.multiply(psuccess, x_pmf)
        row_sums = x_pmf.sum(axis=1)
        x_pmf /= row_sums[:, np.newaxis]
        guess = x[np.argmax(x_pmf, axis=1)]
        fit = (np.matmul(a, guess) + b >= 0).astype(float)
        fit = np.dot(fit, prob_geq_zero) + np.dot(1-fit, 1-prob_geq_zero)
        fitness[z] = fit / fitness_max
        if verbose:
            time_end = time.time()
            error_print("Elapsed time: {:.1f} seconds".format(time_end-time_start))
            error_print("Fitness {:.2f}%".format(fitness[z]*100))
            if solution is not None:
                nb_correct = np.count_nonzero(solution == guess)
                error_print("Number of correctly guessed unknowns: {:d}/{:d}"
                        .format(nb_correct, len(solution)))
        total_iterations += 1
        if (z > 1) and fitness[z-1] >= fitness[z]:
            break
        if nb_correct == len(solution):
            break

    found_solution = (nb_correct == len(solution))
    return guess, found_solution, nb_correct/len(solution), total_iterations


def solve_for_directory(dirpath):
    import os

    # Parameters for Kyber768
    kyber_n = 256
    kyber_k = 3
    kyber_eta1 = 2

    n_unknowns = kyber_n * kyber_k * 2

    a = np.loadtxt(os.path.join(dirpath, 'a.dat'), 
               delimiter=',', usecols=range(n_unknowns), dtype=np.int16)

    b = np.loadtxt(os.path.join(dirpath, 'b.dat'), 
                   delimiter=',', usecols=range(a.shape[0]), dtype=np.int16)

    is_geq_zero = np.loadtxt(os.path.join(dirpath, 'is_geq_zero.dat'), 
                             delimiter=',', usecols=range(a.shape[0]), dtype=np.int16)


    solution = np.loadtxt(os.path.join(dirpath, 'solution.dat'), 
                         delimiter=',', usecols=range(a.shape[1]), dtype=np.int16)

    time_start = time.time()

    n_inequalities = a.shape[0]
    guess, found_solution, fraction_of_solution_recovered, n_iterations = (
        solve_inequalities(kyber_eta1, a, b, is_geq_zero, solution=solution))

    time_end = time.time()


    print('Belief Propagation', end=',')
    print(n_inequalities, end=',')
    print(found_solution, end=',')
    print(fraction_of_solution_recovered, end=',')
    print(n_iterations, end=',')
    print('%.2lf' % (time_end - time_start), end='')
    print()

def print_header():
    print("algorithm,", end='')
    print("n_inequalities,", end='')
    print("recovered_key,", end='')
    print("fraction_of_solution_recovered,", end='')
    print("n_iterations,", end='')
    print("time_seconds_solve_inequalities", end='')
    print()

if __name__ == '__main__':

    print_header()
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} inequalities_dir')
        sys.exit(1)

    solve_for_directory(sys.argv[1])




