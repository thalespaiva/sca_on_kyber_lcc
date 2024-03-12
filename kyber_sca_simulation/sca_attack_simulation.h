#pragma once

#include <stdint.h>
#include <sys/time.h>

#include "api.h"
#include "solver.h"
#define MOD(a,b) ((((a)%(b))+(b))%(b))

#define CRYPTO_FAILURE  -1

#define MAX_CIPHERTEXTS 1000000000
#define MAX_CIPHERTEXTS_REACHED_ERROR -1

#define CM_N 17 // Dimension of the confusion matrix (possible hamming weights: 0, 1, ..., 15, 16)

#define N_UNKNOWNS (KYBER_K * KYBER_N * 2)

#ifndef SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION
#define MAX_SPREAD_FOR_INEQUALITY 317
#else
#define MAX_SPREAD_FOR_INEQUALITY 317
#endif

#define NUMBER_OF_FIXED_ZERO_BITS_IN_SHUFFLED_ATTACK 3


typedef struct attack_params_s {
    int n_inequalities;
    int n_simulations;
    char *confusion_matrix_filepath;
    double confusion_matrix[CM_N][CM_N];
    // Region of interested for predicted hamming weights is
    // [0, ..., hamming_weight_limit_0] union [hamming_weight_limit_1, ..., 16]
    int hamming_weight_limit_0;
    int hamming_weight_limit_1;
    // Region of interested for the bias is
    // bias_lower_limit <= b[i] <= bias_upper_limit
    int bias_lower_limit;
    int bias_upper_limit;
    uint64_t seed;
} attack_params_t;


// The following definition is used to simulate the attack on the masked implementation
// #define SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION

typedef struct results_s {
    int n_ciphertexts;
    int n_wrong_inequalities;
    int recovered_key;
    double fraction_of_solution_recovered;
    int n_iterations;
    double time_sec_build_inequalities;
    double time_sec_solve_inequalities;
} results_t;


void sca_attack_simulation_init_seed(uint64_t seed);
int run_attack_simulation(attack_params_t *params, int *error_code);
int run_attack_simulation_with_custom_spread(attack_params_t *params, int *error_code, int max_spread);
void print_results_header();
void read_confusion_matrix_file(double cm[CM_N][CM_N],
                                char filename[]);
int build_bias_matrices(int n_runs);
void init_results(results_t *results);
int build_inequalities(inequalities_data_t *inequalities,
                        vector_t *solution,
                        attack_params_t *params,
                        results_t *results,
                        uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                        uint8_t sk[CRYPTO_SECRETKEYBYTES]);
int build_inequalities_with_custom_spread(inequalities_data_t *inequalities,
                                          int max_spread,
                                          vector_t *solution,
                                          attack_params_t *params,
                                          results_t *results,
                                          uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                                          uint8_t sk[CRYPTO_SECRETKEYBYTES]);
void print_results(results_t *results, attack_params_t *params, int max_spread);
void analyze_guess_data_for_results(results_t *results, vector_t *guess, vector_t *solution);

struct timespec;
double get_time_diff_in_seconds(struct timespec begin, struct timespec end);

