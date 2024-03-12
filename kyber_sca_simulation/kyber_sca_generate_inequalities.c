#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "sca_attack_simulation.h"


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

void print_inequalities_to_dir(inequalities_data_t *inequalities, vector_t *solution, int n_ciphertexts) {
    FILE *a_file = fopen("inequalities/a.dat", "w");
    FILE *b_file = fopen("inequalities/b.dat", "w");
    FILE *is_geq_zero_file = fopen("inequalities/is_geq_zero.dat", "w");
    FILE *solution_file = fopen("inequalities/solution.dat", "w");
    FILE *n_ciphertexts_file = fopen("inequalities/number_of_ciphertexts.dat", "w");

    if (!a_file || !b_file || !is_geq_zero_file || !solution_file || !n_ciphertexts_file) {
        fprintf(stderr, "Could not open output files\n");
        exit(1);
    }

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        for (int j = 0; j < 2 * KYBER_N * KYBER_K; j++) {
            fprintf(a_file, "%d,", inequalities->a_transpose.m[j][i]);
        }
        fprintf(a_file, "\n");
    }

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        fprintf(b_file, "%d,", inequalities->b.v[i]);
    }
    fprintf(b_file, "\n");

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        fprintf(is_geq_zero_file, "%d,", inequalities->is_geq_zero.v[i]);
    }
    fprintf(is_geq_zero_file, "\n");

    for (int i = 0; i < solution->n; i++) {
        fprintf(solution_file, "%d,", solution->v[i]);
    }
    fprintf(solution_file, "\n");

    fprintf(n_ciphertexts_file, "%d\n", n_ciphertexts);

    fclose(a_file);
    fclose(b_file);
    fclose(is_geq_zero_file);
    fclose(solution_file);
    fclose(n_ciphertexts_file);
}


void generate_inequalities(attack_params_t *params) {
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    inequalities_data_t inequalities;
    init_inequalities_data(&inequalities, params->n_inequalities);

    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        exit(CRYPTO_FAILURE);
    }

    vector_t solution = {0};
    init_zero_vector(&solution, N_UNKNOWNS);

    results_t results;
    init_results(&results);

    int ret_build_ineq = build_inequalities(&inequalities, &solution, params, &results, pk, sk);

    print_inequalities_to_dir(&inequalities, &solution, results.n_ciphertexts);

    free_vector(&solution);
    free_inequalities_data(&inequalities);

    if (ret_build_ineq == MAX_CIPHERTEXTS_REACHED_ERROR) {
        exit(-1);
    }
}

int main(int argc, char *argv[]) {
    attack_params_t params;

    init_attack_parameters_from_args(&params, argc, argv);
    generate_inequalities(&params);
}
