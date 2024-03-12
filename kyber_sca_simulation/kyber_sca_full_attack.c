#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "sca_attack_simulation.h"


void init_attack_parameters_from_args(attack_params_t *params, int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s n_simulations seed n_inequalities confusion_matrix_filepath\n", argv[0]);
        exit(1);
    }
    params->n_simulations = atoi(argv[1]);
    params->seed = strtoul(argv[2], NULL, 10);
    params->n_inequalities = atoi(argv[3]);
    params->confusion_matrix_filepath = argv[4];

    read_confusion_matrix_file(params->confusion_matrix, params->confusion_matrix_filepath);

    sca_attack_simulation_init_seed(params->seed);
}


int main(int argc, char *argv[]) {
    attack_params_t params;

    init_attack_parameters_from_args(&params, argc, argv);

    print_results_header();

    int max_ciphertext_reached_error = 0;
    run_attack_simulation(&params, &max_ciphertext_reached_error);

    if (max_ciphertext_reached_error) {
        fprintf(stderr, "Maximum number of ciphertexts reached.\n");
        fprintf(stderr, "Skipping this parameter set.\n");
    }
}
