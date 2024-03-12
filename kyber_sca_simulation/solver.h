#pragma once

#include <stdint.h>
#include <stdlib.h>

#define MAX_ITERATIONS 1000

#define MIN_HW_TO_CLASSIFY_NEGATIVE_COEFFS 9

typedef struct matrix_s {
    size_t n_rows;
    size_t n_cols;
    int16_t **m;
} matrix_t;

typedef struct vector_s {
    size_t n;
    int16_t *v;
} vector_t;

typedef struct action_s {
    int index;
    int multiplier;
    int score;
} action_t;

typedef struct inequalities_data_s {
    matrix_t a_transpose;
    vector_t b;
    vector_t is_geq_zero;
    int n_inequalities_added;
} inequalities_data_t;

void print_matrix(matrix_t *matrix);
void print_vector(vector_t *vector);
void read_matrix_from_file(matrix_t *matrix, char filename[]);
void read_vector_from_file(vector_t *vector, char filename[]);
int solve(vector_t *guess, inequalities_data_t *inequalities,
          int eta, vector_t *solution);
void init_zero_vector(vector_t *vector, int n);
void init_zero_matrix(matrix_t *matrix, int n_rows, int n_cols);
void free_vector(vector_t *vector);
void free_matrix(matrix_t *matrix);
void init_inequalities_data(inequalities_data_t *inequalities, int n_inequalities);
void free_inequalities_data(inequalities_data_t *inequalities);
