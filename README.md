# SCA on Kyber with Low-Cost Countermeasures

This project contains the source code for our paper

>   Ravi, P., Paiva, T., Jap, D., D’Anvers, J.-P., & Bhasin, S. (2024). Defeating Low-Cost Countermeasures
> against Side-Channel Attacks in Lattice-based Encryption: A Case Study on Crystals-Kyber. IACR Transactions
> on Cryptographic Hardware and Embedded Systems, 2024(2), 795–818. https://doi.org/10.46586/tches.v2024.i2.795-818


## Contents

* `belief_propagation_solver_from_roulette/`:
    * `solver.py`: Python solver from Delvaux's Roulette paper (https://github.com/Crypto-TII/roulette)
    * `test_bp_solver.py`: Wrapper to test it with our inputs
* `data/`:
    * `data/confusion_matrices/`: Preliminary confusion matrices corresponding to some SCA setups.
    * `data/gaussian_confusion_matrices/`: Confusion matrices with gaussian noise.
* `kyber_sca_simulation`: C code for simulating the attack.
    * `kyber_sca_simulation/kyber_sca_full_attack.c`: The full attack for given parameters.
    * `kyber_sca_simulation/solver.c`: The new fast solver in C.
    * `kyber_sca_simulation/kyber768/`: Original reference implementation of Kyber.
        * **Notice:** There is a small change in `crypto_kem_enc` to simulate
            the shuffled implementation, triggered by the definition
            `SIMULATE_ATTACK_ON_SHUFFLED_IMPLEMENTATION`.
    * `kyber_sca_simulation/indcpa.c`: Modified source with injected code for simulating SCA information.
* `kyber_sca_simulation`: C code for simulating the attack.

* `results`: CSV files with the results on the number of ciphertexts for successful attacks
* `plotters`: Python scripts to generate the paper plots based on the result files

## Dependencies

Kyber requires OpenSSL (-lcrypto). The solver and attack simulation do not have any dependencies.
However, to use the `clock_gettime(CLOCK_MONOTONIC_RAW, _);` call we define  `#define _XOPEN_SOURCE 700`.
This may be a problem in Windows but it should not be difficult to substitute the timing functions
with appropriate ones.

## Setup

```
$ uname -a
Linux 6.4.11-arch2-1 #1 SMP PREEMPT_DYNAMIC Sat, 19 Aug 2023 15:38:34 +0000 x86_64 GNU/Linux
$ cat /proc/cpuinfo | grep "model name" | head -n 1
model name  : Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz
$ cat /proc/meminfo | head -n 1
MemTotal:       32789148 kB
$ gcc --version | head -n 1
gcc (GCC) 13.2.1 20230801
```

## Compiling

```
$ cd kyber_sca_simulation
$ cmake -B build
$ cd build
$ make
```
This will generate a number of executables:

```
build_bias_matrices
build_bias_matrices_masked
find_n_ciphertexts_needed
find_n_ciphertexts_needed_masked
kyber_sca_full_attack
kyber_sca_full_attack_grid
kyber_sca_full_attack_masked
kyber_sca_full_attack_shuffled
kyber_sca_generate_inequalities
kyber_sca_solve_inequalities
```

The simplest ones to use are the `kyber_full_attack*`. These run the full attack, simulating
SCA and then building and solving the inequalities. Each of the 3 executables is
responsible for simulating the attack on the unprotected, masked and shuffled implementation,
respectively.
```
kyber_sca_full_attack
kyber_sca_full_attack_masked
kyber_sca_full_attack_shuffled
```

The executables `find_n_ciphertexts_needed` and `find_n_ciphertexts_needed_masked`
essentially run a binary search to find the average number of ciphertext needed for a successful attack.
Executable `build_bias_matrices` and `build_bias_matrices_masked` are used for generating the matrices
in `kyber_sca_simulation/bias_matrices.h`, that are used for to generate the inequalities for key recovery.

Executables `kyber_sca_generate_inequalities` and `kyber_sca_solve_inequalities` are auxiliary files to
generate inequalities for other solvers to


## Usage

The three `kyber_full_attack*` have a similar usage.
```
$ ./kyber_sca_full_attack
Usage: ./kyber_sca_full_attack n_simulations seed n_inequalities confusion_matrix_filepath
```
The parameters meaning are as follows:

* `n_simulations`: Number of secret keys to attack for each parameter set
* `seed`: A seed used to initialize `randombytes` (`uint64_t`)
* `n_inequalities`: Number of inequalities to generate
* `confusion_matrix_filepath`: Path to the confusion matrix used to simulate errors in SCA measurement


## Examples

Right now, the solver outputs some extra information to `stderr`.
So in this README we will use `2> /dev/null` to redirect the `stderr` output and get a cleaner
output.

Here we use the `./kyber_sca_full_attack` to recover 10 keys using 20000 inequalities
and assuming perfect classification. Notice that the output is a  CSV file, that can then
be used for plotting.

In this case, all keys were recovered with less than 350 ciphertexts.

```
$ ./kyber_sca_full_attack 10 1 20000 ../../data/gaussian_confusion_matrices/scale_0.00.csv 2> /dev/null
confusion_matrix_filepath,spread,n_inequalities,n_ciphertexts,n_wrong_inequalities,recovered_key,fraction_of_solution_recovered,n_iterations,time_seconds_build_inequalities,time_seconds_solve_inequalities,max_ciphertext_exceeded
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,328,1,True,1.00,40,0.30,9.97,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,333,0,True,1.00,70,0.30,16.17,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,333,0,True,1.00,160,0.30,36.12,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,335,0,True,1.00,50,0.30,11.98,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,340,0,True,1.00,170,0.31,74.91,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,333,0,True,1.00,50,0.31,12.36,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,333,0,True,1.00,70,0.30,16.25,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,338,0,True,1.00,71,0.31,16.61,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,333,0,True,1.00,51,0.30,12.45,False
../../data/gaussian_confusion_matrices/scale_0.00.csv,317,20000,335,0,True,1.00,70,0.31,16.57,False
```
