#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "sca_attack_simulation.h"


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <n_runs>\n", argv[0]);
        exit(1);
    }
    sca_attack_simulation_init_seed(123456);
    int n_runs = atoi(argv[1]);
    build_bias_matrices(n_runs);
}
