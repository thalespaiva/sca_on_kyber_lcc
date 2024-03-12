#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include "sca_attack_simulation.h"


void read_inequalities_from_dir(inequalities_data_t *inequalities, vector_t *solution) {
    FILE *a_file = fopen("inequalities/a.dat", "r");
    FILE *b_file = fopen("inequalities/b.dat", "r");
    FILE *is_geq_zero_file = fopen("inequalities/is_geq_zero.dat", "r");
    FILE *solution_file = fopen("inequalities/solution.dat", "r");


    if (!a_file || !b_file || !is_geq_zero_file || !solution_file) {
        fprintf(stderr, "Could not open output files\n");
        exit(1);
    }

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        for (int j = 0; j < 2 * KYBER_N * KYBER_K; j++) {
            fscanf(a_file, "%hd,", &inequalities->a_transpose.m[j][i]);
        }
        fscanf(a_file, "\n");
    }

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        fscanf(b_file, "%hd,", &inequalities->b.v[i]);
    }
    fscanf(b_file, "\n");

    for (int i = 0; i < inequalities->n_inequalities_added; i++) {
        fscanf(is_geq_zero_file, "%hd,", &inequalities->is_geq_zero.v[i]);
    }
    fscanf(is_geq_zero_file, "\n");

    for (int i = 0; i < solution->n; i++) {
        fscanf(solution_file, "%hd,", &solution->v[i]);
    }
    fscanf(solution_file, "\n");

    fclose(a_file);
    fclose(b_file);
    fclose(is_geq_zero_file);
    fclose(solution_file);
}

void print_solver_results_header() {
    printf("algorithm,");
    printf("n_inequalities,");
    printf("recovered_key,");
    printf("fraction_of_solution_recovered,");
    printf("n_iterations,");
    printf("time_seconds_solve_inequalities");
    printf("\n");
}

void print_solver_results(results_t *results, int n_inequalities) {
    printf("Greedy Search,");
    printf("%d,", n_inequalities);
    if (results->recovered_key) printf("True,");
    else printf("False,");
    printf("%0.2lf,", results->fraction_of_solution_recovered);
    printf("%d,", results->n_iterations);
    printf("%0.2lf", results->time_sec_solve_inequalities);
    printf("\n");
}

int solve_inequalities(int n_inequalities) {
    inequalities_data_t inequalities;
    init_inequalities_data(&inequalities, n_inequalities);

    vector_t solution = {0};
    init_zero_vector(&solution, N_UNKNOWNS);

    results_t results;
    init_results(&results);

    inequalities.n_inequalities_added = n_inequalities;
    read_inequalities_from_dir(&inequalities, &solution);
    
    struct timespec begin_solve_inequalities_time;
    clock_gettime(CLOCK_MONOTONIC, &begin_solve_inequalities_time);

    vector_t guess;
    init_zero_vector(&guess, N_UNKNOWNS);

    results.n_iterations = solve(&guess, &inequalities, KYBER_ETA1, &solution);

    struct timespec end_solve_inequalities_time;
    clock_gettime(CLOCK_MONOTONIC, &end_solve_inequalities_time);

    analyze_guess_data_for_results(&results, &guess, &solution);

    results.time_sec_solve_inequalities = get_time_diff_in_seconds(begin_solve_inequalities_time,
                                                                   end_solve_inequalities_time);

    free_vector(&solution);
    free_inequalities_data(&inequalities);

    print_solver_results(&results, n_inequalities);

    return results.recovered_key;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s n_inequalities\n", argv[0]);
        exit(1);
    }
    int n_inequalities = atoi(argv[1]);
    
    print_solver_results_header();
    solve_inequalities(n_inequalities);
}
