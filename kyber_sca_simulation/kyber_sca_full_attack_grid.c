#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "sca_attack_simulation.h"

void init_attack_parameters_from_args(attack_params_t *params, int *spread, int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s n_simulations seed confusion_matrix_filepath spread\n", argv[0]);
        exit(1);
    }
    params->n_simulations = atoi(argv[1]);
    params->seed = strtoul(argv[2], NULL, 10);
    *spread = atoi(argv[3]);
    params->confusion_matrix_filepath = argv[4];
    read_confusion_matrix_file(params->confusion_matrix, params->confusion_matrix_filepath);

    sca_attack_simulation_init_seed(params->seed);

    printf("# Running attacks with n_simulations = %d, seed = %lu, confusion_matrix_filepath = %s\n",
           params->n_simulations, params->seed, params->confusion_matrix_filepath);
}

int main(int argc, char *argv[]) {

    attack_params_t params;
    int spread = -1;
    init_attack_parameters_from_args(&params, &spread, argc, argv);

    print_results_header();
    int max_ciphertext_reached_error = 0;

    // int spreads[] = {0, 255, 297, 308, 317, 572, 577, 584, 586, 589, 592, 601, 630, 676};
    // int n_spreads = sizeof(spreads) / sizeof(*spreads);

    // for (int i_spread = 0; i_spread < n_spreads; i_spread++) {
    for (int n_inequalities = 3000; n_inequalities <= 50000; n_inequalities += 1000) {
        params.n_inequalities = n_inequalities;
        // int spread = spreads[i_spread];
        int found_all = run_attack_simulation_with_custom_spread(&params, &max_ciphertext_reached_error, spread);

        if (max_ciphertext_reached_error == MAX_CIPHERTEXTS_REACHED_ERROR)
            break;
        if (found_all)
            break;
    }
    // }
    if (max_ciphertext_reached_error) {
        fprintf(stderr, "Maximum number of ciphertexts reached.\n");
        fprintf(stderr, "Skipping this parameter set.\n");
        exit(1);
    }
}
