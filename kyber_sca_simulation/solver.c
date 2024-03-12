#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#include "solver.h"
#include "params.h"

#define N_UNKNOWNS (KYBER_K * KYBER_N * 2)

void init_inequalities_data(inequalities_data_t *inequalities, int n_inequalities) {
    init_zero_matrix(&inequalities->a_transpose, KYBER_K * KYBER_N * 2, n_inequalities);
    init_zero_vector(&inequalities->b, n_inequalities);
    init_zero_vector(&inequalities->is_geq_zero, n_inequalities);
    inequalities->n_inequalities_added = 0;
}

void free_inequalities_data(inequalities_data_t *inequalities) {
    free_matrix(&inequalities->a_transpose);
    free_vector(&inequalities->b);
    free_vector(&inequalities->is_geq_zero);
    inequalities->n_inequalities_added = 0;
}

void print_matrix(matrix_t *matrix) {
    for (size_t i = 0; i < matrix->n_rows; i++) {
        for (size_t j = 0; j < matrix->n_cols; j++) {
            printf("%d ", matrix->m[i][j]);
        }
        printf("\n");
    }
}

void print_vector(vector_t *vector) {
    for (size_t i = 0; i < vector->n; i++) {
        printf("%d ", vector->v[i]);
    }
    printf("\n");
}

void print_vector_stderr(vector_t *vector) {
    for (size_t i = 0; i < vector->n; i++) {
        fprintf(stderr, "%d ", vector->v[i]);
    }
    fprintf(stderr, "\n");
}

void read_matrix_from_file(matrix_t *matrix, char filename[]) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Could not read matrix input\n");
        exit(1);
    }
    fscanf(f, "%lu\n", &matrix->n_rows);
    fscanf(f, "%lu\n", &matrix->n_cols);
    matrix->m = malloc(matrix->n_rows * sizeof(*(matrix->m)));
    for (size_t i = 0; i < matrix->n_rows; i++) {
        matrix->m[i] = malloc(matrix->n_cols * sizeof(*(matrix->m[i])));
        for (size_t j = 0; j < matrix->n_cols; j++) {
            fscanf(f, "%hd ", &matrix->m[i][j]);
        }
        fscanf(f, "\n");
    }
    fclose(f);
}

void read_vector_from_file(vector_t *vector, char filename[]) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Could not read vector input\n");
        exit(1);
    }
    fscanf(f, "%lu\n", &vector->n);
    vector->v = malloc(vector->n * sizeof(*(vector->v)));
    for (size_t i = 0; i < vector->n; i++) {
        fscanf(f, "%hd\n", &vector->v[i]);
    }
    fclose(f);
}

void compute_action_score(action_t *action,
                          inequalities_data_t *inequalities,
                          vector_t *current_product) {
    matrix_t *a_transpose = &inequalities->a_transpose;
    vector_t *b = &inequalities->b;
    vector_t *target_ineq_value = &inequalities->is_geq_zero;

    int score = 0;
    for (size_t i = 0; i < b->n; i++) {
        int add = action->multiplier * a_transpose->m[action->index][i];
        int value = current_product->v[i] + add + b->v[i];
        int is_geq_zero = target_ineq_value->v[i];
        if ((value >= 0) && (is_geq_zero == 0)) {
            // Lower score based on the distance to satisfy the inequality
            score -= abs(value) + 1;
        }
        if ((value < 0) && (is_geq_zero == 1)) {
            // Lower score based on the distance to satisfy the inequality
            score -= abs(value);
        }
    }
    // printf("action = %d, %d\n", action->index, score);
    action->score = score;
}


void init_zero_vector(vector_t *vector, int n) {
    vector->n = n;
    vector->v = malloc(n * sizeof(*vector->v));
    memset(vector->v, 0, n * sizeof(*vector->v));
}

void free_vector(vector_t *vector) {
    free(vector->v);
    vector->n = 0;
}

void init_zero_matrix(matrix_t *matrix, int n_rows, int n_cols) {
    matrix->n_rows = n_rows;
    matrix->n_cols = n_cols;
    matrix->m = malloc(n_rows * sizeof(*matrix->m));
    for (size_t i = 0; i < matrix->n_rows; i++) {
        matrix->m[i] = malloc(matrix->n_cols * sizeof(*(matrix->m[i])));
        for (int j = 0; j < n_cols; j++) {
            matrix->m[i][j] = 0;
        }
    }
}

void free_matrix(matrix_t *matrix) {
    for (size_t i = 0; i < matrix->n_rows; i++) {
        free(matrix->m[i]);
    }
    free(matrix->m);
    matrix->n_rows = 0;
    matrix->n_cols = 0;
}

int cmp_actions(const void *a, const void *b) {
   return ((const action_t *)b)->score - ((const action_t *)a)->score;
}

int get_number_of_best_actions_to_select(int iteration, int current_n_actions_to_apply) {
    int n_actions_to_apply = current_n_actions_to_apply;
    if ((iteration + 1) % 10 == 0) {
        n_actions_to_apply = n_actions_to_apply / 2;
        n_actions_to_apply = (n_actions_to_apply > 0) ? n_actions_to_apply : 1;
    }
    if ((iteration + 1) % 100 == 0) {
        n_actions_to_apply = 128;
    }
    return n_actions_to_apply;
}


int apply_action_using_best_multiplier(vector_t *guess, vector_t *current_product, inequalities_data_t *inequalities, int eta, int index) {

    int m = inequalities->a_transpose.n_cols;

    int best_score = INT_MIN;
    int best_mult = 1;
    for (int k = -2*eta; k <= 2*eta; k++) {
        if (k == 0) continue;
        action_t action;
        action.index = index;
        action.multiplier = k;
        action.score = INT_MIN;
        if (guess->v[index] + action.multiplier > eta) continue;
        if (guess->v[index] + action.multiplier < -eta) continue;
        compute_action_score(&action, inequalities, current_product);
        if (action.score > best_score) {
            best_score = action.score;
            best_mult = k;
        }
    }

    guess->v[index] += best_mult;
    for (int k = 0; k < m; k++) {
        current_product->v[k] += best_mult * inequalities->a_transpose.m[index][k];
    }

    return best_score;
}

int solve(vector_t *guess, inequalities_data_t *inequalities, int eta, vector_t *SECRET_solution) {

    int n = inequalities->a_transpose.n_rows;
    // int m = inequalities->a_transpose.n_cols;

    memset(guess->v, 0, guess->n * sizeof(*guess->v));

    vector_t current_product;
    init_zero_vector(&current_product, inequalities->a_transpose.n_cols);

    //
    // int n_actions_to_apply = 100;
    int n_actions_to_apply = 128;

    int current_score = INT_MIN;
    int last_score = INT_MIN;
    int n_iterations = 0;

    int n_actions = n * (4*eta);
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        n_iterations++;

        action_t actions[n_actions];
        int action_index = 0;
        for (int index = 0; index < n; index++) {
            for (int value = -2*eta; value <= 2*eta; value++) {
                if (value == 0) {
                    continue;
                }
                actions[action_index].index = index;
                actions[action_index].multiplier = value;
                actions[action_index].score = INT_MIN;

                if (guess->v[index] + actions[action_index].multiplier <= eta) {
                    if (guess->v[index] + actions[action_index].multiplier >= -eta) {
                        compute_action_score(&actions[action_index], inequalities, &current_product);
                    }
                }
                action_index++;
            }
        }

        qsort(actions, n_actions, sizeof(*actions), cmp_actions);

        n_actions_to_apply = get_number_of_best_actions_to_select(i, n_actions_to_apply);

        int n_actions_applied = 0;
        for (int j = 1; j < n_actions; j++) {
            if (n_actions_applied >= n_actions_to_apply) break;
            if (j >= n) break;
            int index = actions[j].index;

            current_score = apply_action_using_best_multiplier(guess, &current_product, inequalities, eta, index);
            n_actions_applied++;
        }

        double diff = (double) (current_score - last_score) / abs(last_score);
        last_score = current_score;

        // This variable is marked as SECRET because it uses the SECRET_solution.
        // A real attacker does not know this value!!!
        // It is only used for testing the convergence.
        size_t SECRET_coeffs_found = 0;
        for (size_t j = 0; j < guess->n; j++) {
            SECRET_coeffs_found += (guess->v[j] == SECRET_solution->v[j]);
        }
        fprintf(stderr, "[%d: n_actions_to_apply %d] score = %d, diff = %0.4lf (secret recovered = %ld / %ld)\n",
                i, n_actions_to_apply, current_score, diff, SECRET_coeffs_found, guess->n);
        if (SECRET_coeffs_found == guess->n) {
            fprintf(stderr, ":^) Key found ! Ç~ [score=%d]\n", current_score);
            break;
        }
    }
    fprintf(stderr, "guess: ");
    print_vector_stderr(guess);

    free_vector(&current_product);

    return n_iterations;
}
