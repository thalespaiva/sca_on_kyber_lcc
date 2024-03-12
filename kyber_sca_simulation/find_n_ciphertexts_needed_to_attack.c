#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include "sca_attack_simulation.h"
#include "solver.h"


void init_attack_parameters_from_args(attack_params_t *params, int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s seed n_inequalities confusion_matrix_filepath\n", argv[0]);
        exit(1);
    }
    params->seed = strtoul(argv[1], NULL, 10);
    params->n_inequalities = atoi(argv[2]);
    params->confusion_matrix_filepath = argv[3];

    read_confusion_matrix_file(params->confusion_matrix, params->confusion_matrix_filepath);

    sca_attack_simulation_init_seed(params->seed);
}

void generate_inequalities(attack_params_t *params, inequalities_data_t *inequalities, vector_t *solution,
                           int *total_n_ciphertexts) {
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;


    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        exit(CRYPTO_FAILURE);
    }

    results_t results;
    init_results(&results);

    int ret_build_ineq = build_inequalities(inequalities, solution, params, &results, pk, sk);

    *total_n_ciphertexts = results.n_ciphertexts;
    if (ret_build_ineq == MAX_CIPHERTEXTS_REACHED_ERROR) {
        exit(-1);
    }
}


void print_solver_results_header() {
    printf("algorithm,");
    printf("seed,");
    printf("n_inequalities,");
    printf("recovered_key,");
    printf("fraction_of_solution_recovered,");
    printf("n_iterations,");
    printf("time_seconds_solve_inequalities,");
    printf("approx_number_of_ciphertexts,");
    printf("confusion_matrix");
    printf("\n");
}

void print_solver_results(results_t *results,
                          int n_inequalities_needed,
                          int total_n_inequalities,
                          int total_n_ciphertexts,
                          attack_params_t *params) {

    printf("Greedy Search,");
    printf("%ld,", params->seed);
    printf("%d,", n_inequalities_needed);
    if (results->recovered_key) printf("True,");
    else printf("False,");
    printf("%0.2lf,", results->fraction_of_solution_recovered);
    printf("%d,", results->n_iterations);
    printf("%0.2lf,", results->time_sec_solve_inequalities);
    printf("%0.2lf,", (double) total_n_ciphertexts * n_inequalities_needed / total_n_inequalities );
    printf("%s", params->confusion_matrix_filepath);
    printf("\n");
}

int set_number_of_inequalities(inequalities_data_t *inequalities, int n_inequalities) {
    int old_number_of_inequalities = inequalities->n_inequalities_added;

    inequalities->a_transpose.n_cols = n_inequalities;
    inequalities->b.n = n_inequalities;
    inequalities->is_geq_zero.n = n_inequalities;
    inequalities->n_inequalities_added = n_inequalities;

    return old_number_of_inequalities;
};

int solve_inequalities(inequalities_data_t *inequalities, vector_t *solution, int n_inequalities,
                       int total_n_ciphertexts, attack_params_t *params) {

    results_t results;
    init_results(&results);

    struct timespec begin_solve_inequalities_time;
    clock_gettime(CLOCK_MONOTONIC, &begin_solve_inequalities_time);

    vector_t guess;
    init_zero_vector(&guess, N_UNKNOWNS);

    int total_n_inequalities = set_number_of_inequalities(inequalities, n_inequalities);
    results.n_iterations = solve(&guess, inequalities, KYBER_ETA1, solution);
    set_number_of_inequalities(inequalities, total_n_inequalities);


    struct timespec end_solve_inequalities_time;
    clock_gettime(CLOCK_MONOTONIC, &end_solve_inequalities_time);

    analyze_guess_data_for_results(&results, &guess, solution);

    results.time_sec_solve_inequalities = get_time_diff_in_seconds(begin_solve_inequalities_time,
                                                                   end_solve_inequalities_time);

    print_solver_results(&results, n_inequalities, total_n_inequalities, total_n_ciphertexts,
                         params);

    return results.recovered_key;
}

int find_n_ciphertexts_needed_to_attack(inequalities_data_t *inequalities, vector_t *solution,
                                        int total_n_ciphertexts, attack_params_t *params) {

    int is_solvable = solve_inequalities(inequalities, solution, inequalities->n_inequalities_added,
                                         total_n_ciphertexts, params);
    if (!is_solvable) {
        fprintf(stderr, "Need more inequalities!!!!");
        exit(1);
    }

    int left = 0;
    int right = inequalities->n_inequalities_added;

    while (left < right) {
        int mid = (left + right) / 2;
        int found_key = solve_inequalities(inequalities, solution, mid, total_n_ciphertexts, params);
        if (found_key) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
        // printf("left, right = %d, %d\n", left, right);
    }
    assert(left == right);
    return right;
}

int main(int argc, char *argv[]) {
    attack_params_t params;

    init_attack_parameters_from_args(&params, argc, argv);

    inequalities_data_t inequalities;
    init_inequalities_data(&inequalities, params.n_inequalities);

    vector_t solution = {0};
    init_zero_vector(&solution, N_UNKNOWNS);

    int total_n_ciphertexts;
    generate_inequalities(&params, &inequalities, &solution, &total_n_ciphertexts);

    print_solver_results_header();
    find_n_ciphertexts_needed_to_attack(&inequalities, &solution, total_n_ciphertexts, &params);

    free_vector(&solution);
    free_inequalities_data(&inequalities);
}
