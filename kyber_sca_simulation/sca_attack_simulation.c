#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <math.h>

#include "api.h"
#include "rng.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"

#include "solver.h"
#include <math.h>

#include "sca_attack_simulation.h"

#include "bias_matrices.h"

#include <limits.h>


int hamming_weight_int16(int16_t t);
int mod_centered(int x);

uint64_t random64();
double random_in_0_1(void);

void read_confusion_matrix_file(double cm[CM_N][CM_N],
                                char filename[]);
int sample_predicted_from_true_value(double confusion_matrix[CM_N][CM_N], int true_hamming_weight);
void get_noisy_sca_sample(attack_params_t *params, inequalities_data_t *inequalities,
                          results_t *results, int max_spread);
int build_inequalities(inequalities_data_t *inequalities, vector_t *solution, attack_params_t *params, results_t *results,
                       uint8_t pk[CRYPTO_PUBLICKEYBYTES], uint8_t sk[CRYPTO_SECRETKEYBYTES]);
int get_message_bit(uint8_t message[], int bit_pos);
int is_wrong_inequality(int noisy_message_coeff, int message_bit, int is_geq_zero);
void write_solution(vector_t *solution, polyvec *s, polyvec *e);
void get_minus_e1_minus_delta_u(polyvec *minus_e1_minus_delta_u, polyvec *e1, polyvec *delta_u);
void write_a_row_in_inequalities(inequalities_data_t *inequalities, int row_index,
                                 polyvec *minus_e1_minus_delta_u, polyvec *r);

double get_time_diff_in_seconds(struct timespec begin, struct timespec end);


void sca_attack_simulation_init_seed(uint64_t seed) {
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++)
        entropy_input[i] = seed >> i;
    randombytes_init(entropy_input, NULL, 256);
}


// Global variables that are used to extract the values known by the attacker
// and the secret information from the Kyber implementation.

polyvec global__delta_u = {0};                        // Attacker knows
poly global__delta_v = {0};                           // Attacker knows
polyvec global__r = {0};                              // Attacker knows
polyvec global__e1 = {0};                             // Attacker knows
poly global__e2 = {0};                                // Attacker knows
uint8_t global__message[KYBER_INDCPA_MSGBYTES] = {0}; // Attacker knows


// BEGIN SECRET VARIABLES =========================================================================

// BE CAREFUL WITH THE SECRET INFORMATION BELOW
// The secret key (global__s, global__e) must only be used to
// analyze the convergence of the solver.
polyvec global__s = {0};                              // SECRET: USE CAREFULLY
polyvec global__e = {0};                              // SECRET: USE CAREFULLY

// The global__noisy_message contains the noisy coefficients (before decoding the message).
// The values of the coefficients are not known to the attacker!
// The attacker must learn only a `predicted` Hamming Weight of the coefficients in the
// the Side-Channel simulation. The prediction is done using a confusion matrix that
// was generated for a real SCA setup.
poly global__noisy_message = {0};                     // SECRET: USE CAREFULLY


#ifdef SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION

// USED WHEN ATTACKING MASKED IMPLEMENTATION
poly global__share0_noisy_message = {0};                     // SECRET: USE CAREFULLY
poly global__share1_noisy_message = {0};                     // SECRET: USE CAREFULLY

#endif

// END SECRET VARIABLES =========================================================================

void print_perfect_samples_for_testing(int);

void init_results(results_t *results) {
    results->n_ciphertexts = 0;
    results->n_wrong_inequalities = 0;
    results->recovered_key = 0;
    results->fraction_of_solution_recovered = 0;
    results->n_iterations = 0;
    results->time_sec_build_inequalities = 0;
    results->time_sec_solve_inequalities = 0;
}

int hamming_weight_int16(int16_t t) {
    int hw = __builtin_popcount(t); // In 32 bits
    if (t < 0)
        hw -= 16;
    return hw;
}

void read_confusion_matrix_file(double cm[CM_N][CM_N],
                               char filename[]) {

    FILE *cm_file = fopen(filename, "r");
    if (!cm_file) {
        fprintf(stderr, "Error reading confusion matrix\n");
        exit(1);
    }
    char info_row_discarded[1000];
    fgets(info_row_discarded, 1000, cm_file);
    for (int i = 0; i < CM_N; i++) {
        double row_sum = 0;
        for (int j = 0; j < CM_N; j++) {
            fscanf(cm_file, "%lf ", &cm[i][j]);
            row_sum += cm[i][j];
        }
        for (int j = 0; j < CM_N; j++) {
            cm[i][j] /= row_sum;
        }
        fscanf(cm_file, "\n");
    }
    fprintf(stderr, "Read confusion matrix:\n");
    for (int i = 0; i < CM_N; i++) {
        for (int j = 0; j < CM_N; j++) {
            fprintf(stderr, "%lf ", cm[i][j]);
        }
        fprintf(stderr, "\n");
    }
    fclose(cm_file);
}

int mod_centered(int x) {
    int c = KYBER_Q/2;
    return MOD(x + c, KYBER_Q) - c;
}

uint64_t random64() {
    uint8_t a[8] = {0};
    randombytes(a, 8);
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) {
        r += ((uint64_t) a[i]) << (8 * i);
    }
    return r;
}

// Extracted from https://mumble.net/~campbell/2014/04/28/random_real.c;
double random_in_0_1(void) {
    return (random64() & ((1ULL << 53) - 1)) * ldexp(1, -53);
}

int sample_predicted_from_true_value(double confusion_matrix[CM_N][CM_N],
                                     int true_hamming_weight) {

    double r = random_in_0_1();

    double cummulative = 0;
    for (int i = 0; i < CM_N; i++) {
        cummulative += confusion_matrix[true_hamming_weight][i];
        if (r < cummulative)
            return i;
    }
    assert (fabs(1 - cummulative) < 0.00001);
    return CM_N - 1;
}

void test_sample_predicted(double confusion_matrix[CM_N][CM_N]) {
    for (int j = 0; j < CM_N; j++) {
        printf("%d: ", j);
        for (int i = 0; i < 8; i++) {
            printf("%d, ", sample_predicted_from_true_value(confusion_matrix, j));
        }
        printf("\n");
    }
}


int build_inequalities(inequalities_data_t *inequalities,
                        vector_t *solution,
                        attack_params_t *params,
                        results_t *results,
                        uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                        uint8_t sk[CRYPTO_SECRETKEYBYTES]) {

    return build_inequalities_with_custom_spread(inequalities, MAX_SPREAD_FOR_INEQUALITY,
                                                 solution, params, results, pk, sk);
}

int build_inequalities_with_custom_spread(inequalities_data_t *inequalities,
                                          int max_spread,
                                          vector_t *solution,
                                          attack_params_t *params,
                                          results_t *results,
                                          uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                                          uint8_t sk[CRYPTO_SECRETKEYBYTES]) {

    uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    int ret_val = 0;

    write_solution(solution, &global__s, &global__e);

    for (int n_ciphertexts = 1; n_ciphertexts <= MAX_CIPHERTEXTS; n_ciphertexts++) {
        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            exit(CRYPTO_FAILURE);
        }
        get_noisy_sca_sample(params, inequalities, results, max_spread);

        results->n_ciphertexts = n_ciphertexts;
        if (inequalities->n_inequalities_added >= params->n_inequalities)
            break;
    }
    // assert(inequalities->n_inequalities_added == params->n_inequalities);
    if (inequalities->n_inequalities_added != params->n_inequalities)
        return MAX_CIPHERTEXTS_REACHED_ERROR;

    return 0;
}

void analyze_guess_data_for_results(results_t *results, vector_t *guess, vector_t *solution) {
    assert (solution->n == guess->n);

    size_t n_secret_recovered = 0;
    for (size_t i = 0; i < guess->n; i++) {
        n_secret_recovered += (guess->v[i] == solution->v[i]);
    }
    results->fraction_of_solution_recovered = (double) n_secret_recovered / solution->n;
    results->recovered_key = (n_secret_recovered == solution->n);
}

double get_time_diff_in_seconds(struct timespec begin, struct timespec end) {
    return (end.tv_nsec - begin.tv_nsec) / 1000000000.0 + (end.tv_sec  - begin.tv_sec);
}

void print_results_header() {
    printf("confusion_matrix_filepath,");
    printf("spread,");
    printf("n_inequalities,");
    printf("n_ciphertexts,");
    printf("n_wrong_inequalities,");
    printf("recovered_key,");
    printf("fraction_of_solution_recovered,");
    printf("n_iterations,");
    printf("time_seconds_build_inequalities,");
    printf("time_seconds_solve_inequalities,");
    printf("max_ciphertext_exceeded");
    printf("\n");
}


void print_results(results_t *results, attack_params_t *params, int max_spread) {
    printf("%s,", params->confusion_matrix_filepath);
    printf("%d,", max_spread);
    printf("%d,", params->n_inequalities);
    printf("%d,", results->n_ciphertexts);
    printf("%d,", results->n_wrong_inequalities);
    if (results->recovered_key) printf("True,");
    else printf("False,");
    printf("%0.2lf,", results->fraction_of_solution_recovered);
    printf("%d,", results->n_iterations);
    printf("%0.2lf,", results->time_sec_build_inequalities);
    printf("%0.2lf,", results->time_sec_solve_inequalities);
    if (results->n_ciphertexts >= MAX_CIPHERTEXTS) printf("True");
    else printf("False");
    printf("\n");
}

int run_attack_simulation(attack_params_t *params, int *error_code) {
    return run_attack_simulation_with_custom_spread(params, error_code, MAX_SPREAD_FOR_INEQUALITY);
}

int run_attack_simulation_with_custom_spread(attack_params_t *params, int *error_code, int max_spread) {
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    int n_key_found = 0;
    for (int i = 0; i < params->n_simulations; i++) {
        inequalities_data_t inequalities;
        init_inequalities_data(&inequalities, params->n_inequalities);

        results_t results;
        init_results(&results);

        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }

        struct timespec begin_build_inequalities_time;
        clock_gettime(CLOCK_MONOTONIC, &begin_build_inequalities_time);

        vector_t solution = {0};
        init_zero_vector(&solution, N_UNKNOWNS);

        int ret_build_ineq = build_inequalities_with_custom_spread(&inequalities, max_spread, &solution, params, &results, pk, sk);

        struct timespec end_build_inequalities_time;
        clock_gettime(CLOCK_MONOTONIC, &end_build_inequalities_time);

        struct timespec begin_solve_inequalities_time;
        clock_gettime(CLOCK_MONOTONIC, &begin_solve_inequalities_time);

        vector_t guess;
        init_zero_vector(&guess, N_UNKNOWNS);
        fprintf(stderr, "n_wrong = %d / %d results\n", results.n_wrong_inequalities, params->n_inequalities);
        fprintf(stderr, "ciphertexts: %d\n", results.n_ciphertexts);

        results.n_iterations = solve(&guess, &inequalities, KYBER_ETA1, &solution);

        struct timespec end_solve_inequalities_time;
        clock_gettime(CLOCK_MONOTONIC, &end_solve_inequalities_time);

        analyze_guess_data_for_results(&results, &guess, &solution);


        results.time_sec_build_inequalities = get_time_diff_in_seconds(begin_build_inequalities_time,
                                                                       end_build_inequalities_time);
        results.time_sec_solve_inequalities = get_time_diff_in_seconds(begin_solve_inequalities_time,
                                                                       end_solve_inequalities_time);
        n_key_found += results.recovered_key;

        free_vector(&solution);
        free_vector(&guess);
        free_inequalities_data(&inequalities);

        print_results(&results, params, max_spread);
        fflush(stdout);

        if (ret_build_ineq == MAX_CIPHERTEXTS_REACHED_ERROR) {
            *error_code = MAX_CIPHERTEXTS_REACHED_ERROR;
            break;
        }
    }

    return (n_key_found == params->n_simulations);
}


#ifndef SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION

// This function is used to build the bias matrices. It has nothing to
// do with SCA, and the resulting matrices are used during key recovery when building inequalities.
int build_bias_matrices(int n_runs) {
    int ret_val;

    int max_noisy_coeff_for_hw[17] = {0};
    int min_noisy_coeff_for_hw[17] = {0};

    for (int i = 0; i < 17; i++) {
        max_noisy_coeff_for_hw[i] = INT_MIN;
        min_noisy_coeff_for_hw[i] = INT_MAX;
    }

    for (int k = 0; k < n_runs; k++) {

        unsigned char  pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }

        uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            exit(CRYPTO_FAILURE);
        }

        for (int i = 0; i < KYBER_N; i++) {
            if (get_message_bit(global__message, i) == 1) continue;

            int true_noisy_coeff_hw = hamming_weight_int16(global__noisy_message.coeffs[i]);
            int noisy_coeff = mod_centered(global__noisy_message.coeffs[i]);

            if (noisy_coeff > max_noisy_coeff_for_hw[true_noisy_coeff_hw]) {
                max_noisy_coeff_for_hw[true_noisy_coeff_hw] = noisy_coeff;
            }
            if (noisy_coeff < min_noisy_coeff_for_hw[true_noisy_coeff_hw]) {
                min_noisy_coeff_for_hw[true_noisy_coeff_hw] = noisy_coeff;
            }
        }
    }

    printf("int MAX_NOISY_COEFF_FOR_SHARES_HWS[17] = {\n");
    for (int j = 0; j < 17; j++) {
        printf("%4d", max_noisy_coeff_for_hw[j]);
        if (j < 16) printf(", ");
    }
    printf("\n");
    printf("};\n");

    printf("int MIN_NOISY_COEFF_FOR_SHARES_HWS[17] = {\n");
    for (int j = 0; j < 17; j++) {
        printf("%4d", min_noisy_coeff_for_hw[j]);
        if (j < 16) printf(", ");
    }
    printf("\n");
    printf("};\n");

    return 0;
}

#else

int build_bias_matrices(int n_runs) {
    int ret_val;

    int max_noisy_coeff_for_hw[17][17][800] = {0};
    int min_noisy_coeff_for_hw[17][17][800] = {0};

    for (int k = 0; k < n_runs; k++) {

        unsigned char  pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }

        uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            exit(CRYPTO_FAILURE);
        }
        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            exit(CRYPTO_FAILURE);
        }

        for (int i = 0; i < KYBER_N; i++) {
            if (get_message_bit(global__message, i) == 1) continue;

            int share0_hw = hamming_weight_int16(global__share0_noisy_message.coeffs[i]);
            int share1_hw = hamming_weight_int16(global__share1_noisy_message.coeffs[i]);

            int noisy_coeff = mod_centered(global__noisy_message.coeffs[i]);
            if (abs(noisy_coeff) >= 400) continue;
            max_noisy_coeff_for_hw[share0_hw][share1_hw][noisy_coeff + 400]++;
            min_noisy_coeff_for_hw[share0_hw][share1_hw][noisy_coeff + 400]++;
        }
    }

    int max_noisy_coeff_for_hw_mat[17][17] = {0};
    int min_noisy_coeff_for_hw_mat[17][17] = {0};

    double frac = 1;

    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 17; j++) {
            max_noisy_coeff_for_hw_mat[i][j] = INT_MIN;
            min_noisy_coeff_for_hw_mat[i][j] = INT_MAX;
        }
    }
    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 17; j++) {
            double sum = 0;
            for (int k = 0; k < 800; k++) {
                sum += max_noisy_coeff_for_hw[i][j][k];
            }
            double cumm = 0;
            for (int k = 0; k < 800; k++) {
                cumm += max_noisy_coeff_for_hw[i][j][k];
                if (cumm/sum >= frac) {
                    max_noisy_coeff_for_hw_mat[i][j] = k - 400;
                    break;
                }
            }
        }
    }

    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 17; j++) {
            double sum = 0;
            for (int k = 0; k < 800; k++) {
                sum += min_noisy_coeff_for_hw[i][j][k];
            }
            double cumm = 0;
            for (int k = 800 - 1; k >= 0; k--) {
                cumm += min_noisy_coeff_for_hw[i][j][k];
                if (cumm/sum >= frac) {
                    min_noisy_coeff_for_hw_mat[i][j] = k - 400;
                    break;
                }
            }
        }
    }

    printf("int MAX_NOISY_COEFF_FOR_SHARES_HWS[17][17] = {\n");
    for (int i = 0; i < 17; i++) {
        printf("    { ");
        for (int j = 0; j < 17; j++) {
           printf("%4d", max_noisy_coeff_for_hw_mat[i][j]);
            if (j < 16) printf(", ");
        }
        printf(" }");
        if (i == 16) printf("\n");
        else printf(",\n");
    }
    printf("};\n");
    printf("int MIN_NOISY_COEFF_FOR_SHARES_HWS[17][17] = {\n");
    for (int i = 0; i < 17; i++) {
        printf("    { ");
        for (int j = 0; j < 17; j++) {
           printf("%4d", min_noisy_coeff_for_hw_mat[i][j]);
           if (j < 16) printf(", ");
        }
        printf(" }");
        if (i == 16) printf("\n");
        else printf(",\n");
    }
    printf("};\n");
    return 0;
}

#endif

int get_message_bit(uint8_t message[], int bit_pos) {
    return (message[(bit_pos / 8)] >> (bit_pos % 8)) & 1;
}

void get_minus_e1_minus_delta_u(polyvec *minus_e1_minus_delta_u, polyvec *e1, polyvec *delta_u) {
    for (int k = 0; k < KYBER_K; k++) {
        for(int i = 0; i < KYBER_N/8; i++) {
            for(int j = 0; j < 8; j++) {
                int16_t t_e1 = e1->vec[k].coeffs[8 * i + j];
                int16_t t_delta_u = delta_u->vec[k].coeffs[8 * i + j];
                minus_e1_minus_delta_u->vec[k].coeffs[8 * i + j] = - t_e1 - t_delta_u;
            }
        }
    }
}

void write_a_row_in_inequalities(inequalities_data_t *inequalities, int row_index,
                                 polyvec *minus_e1_minus_delta_u, polyvec *r) {

    int i_col = 0;
    int i_row = inequalities->n_inequalities_added;
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = row_index; i >= 0; i--) {
            inequalities->a_transpose.m[i_col++][i_row] =
                    mod_centered(minus_e1_minus_delta_u->vec[k].coeffs[i]);
        }
        for (int i = KYBER_N - 1; i >= row_index + 1; i--) {
            inequalities->a_transpose.m[i_col++][i_row] =
                    mod_centered(-minus_e1_minus_delta_u->vec[k].coeffs[i]);
        }
    }
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = row_index; i >= 0; i--) {
            inequalities->a_transpose.m[i_col++][i_row] =
                    mod_centered(r->vec[k].coeffs[i]);
        }
        for (int i = KYBER_N - 1; i >= row_index + 1; i--) {
            inequalities->a_transpose.m[i_col++][i_row] =
                    mod_centered(-r->vec[k].coeffs[i]);
        }
    }
}

void write_solution(vector_t *solution, polyvec *s, polyvec *e) {
    int i_solution = 0;
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = 0; i < KYBER_N; i++) {
            solution->v[i_solution++] = mod_centered(s->vec[k].coeffs[i]);
        }
    }
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = 0; i < KYBER_N; i++) {
            solution->v[i_solution++] = mod_centered(e->vec[k].coeffs[i]);
        }
    }
}

int is_wrong_inequality(int noisy_message_coeff, int is_geq_zero, int term) {
    int noise = mod_centered(noisy_message_coeff);

    return ((noise - term >= 0) != is_geq_zero);
}


#if !defined(SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION) && !defined(SIMULATE_ATTACK_ON_SHUFFLED_IMPLEMENTATION)

void get_noisy_sca_sample(attack_params_t *params, inequalities_data_t *inequalities,
                          results_t *results, int max_spread) {

    polyvec minus_e1_minus_delta_u = {0};
    get_minus_e1_minus_delta_u(&minus_e1_minus_delta_u, &global__e1, &global__delta_u);

    for (int i = 0; i < KYBER_N; i++) {
        if (get_message_bit(global__message, i) == 1) continue;

        int true_noisy_coeff_hw = hamming_weight_int16(global__noisy_message.coeffs[i]);
        int predicted_noisy_coeff_hw = sample_predicted_from_true_value(params->confusion_matrix,
                                                                        true_noisy_coeff_hw);
        int16_t bias = global__e2.coeffs[i] + global__delta_v.coeffs[i];

        int max_message_coeff_given_HW = MAX_NOISY_COEFF_FOR_SHARES_HWS[predicted_noisy_coeff_hw];
        int min_message_coeff_given_HW = MIN_NOISY_COEFF_FOR_SHARES_HWS[predicted_noisy_coeff_hw];

        int spread = (max_message_coeff_given_HW - min_message_coeff_given_HW);
        if (spread > max_spread)
            continue;

        fprintf(stderr, "n_inequalities = %d\n", inequalities->n_inequalities_added);
        fprintf(stderr, "n_ciphertexts = %d\n", results->n_ciphertexts);
        for (int k = 0; k < 2; k++) {
            int n_ineq_added = inequalities->n_inequalities_added;
            if (inequalities->n_inequalities_added == params->n_inequalities)
                break;
            if (k == 0) {
                if (max_message_coeff_given_HW > MAX_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - max_message_coeff_given_HW - 1);
                inequalities->is_geq_zero.v[n_ineq_added] = 0;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   max_message_coeff_given_HW + 1);
                results->n_wrong_inequalities += is_wrong;
            }
            if (k == 1) {
                if (min_message_coeff_given_HW < MIN_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - min_message_coeff_given_HW);
                inequalities->is_geq_zero.v[n_ineq_added] = 1;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   min_message_coeff_given_HW);
                results->n_wrong_inequalities += is_wrong;
            }
        }
        if (inequalities->n_inequalities_added == params->n_inequalities)
            break;
    }
}

#elif defined(SIMULATE_ATTACK_ON_SHUFFLED_IMPLEMENTATION)

#define HIGH_MIN 15
#define LOW_MAX 1

#define N_EXTREME_VALUES_TO_ACCEPT_INEQUALITIES 2

void get_noisy_sca_sample(attack_params_t *params, inequalities_data_t *inequalities,
                          results_t *results, int max_spread) {

    polyvec minus_e1_minus_delta_u = {0};
    get_minus_e1_minus_delta_u(&minus_e1_minus_delta_u, &global__e1, &global__delta_u);

    int count_high_hw = 0;
    int count_low_hw = 0;

    // Careful: loop above simulates the extraction of knowledge when entries are shuffled
    for (int i = 0; i < KYBER_N; i++) {
        // Counts the number of very high and very low Hamming weights observed
        int true_noisy_coeff_hw = hamming_weight_int16(global__noisy_message.coeffs[i]);
        int predicted_noisy_coeff_hw = sample_predicted_from_true_value(params->confusion_matrix,
                                                                        true_noisy_coeff_hw);

        if (predicted_noisy_coeff_hw >= HIGH_MIN) count_high_hw++;
        if (predicted_noisy_coeff_hw <= LOW_MAX) count_low_hw++;
    }
    // Careful: no information on predicted_noisy_coeff_hw should be available outside the loop above

    // Only information out is count_high_hw and count_low_hw

    // Decides whether we are seeing a case of all high or all low values
    int high_case = 0;
    int low_case = 0;

    if (count_high_hw == N_EXTREME_VALUES_TO_ACCEPT_INEQUALITIES && count_low_hw == 0) high_case = 1;
    else if (count_low_hw == N_EXTREME_VALUES_TO_ACCEPT_INEQUALITIES && count_high_hw == 0) low_case = 1;

    // In case we are not in these cases, return
    if (!high_case && !low_case) return;

    for (int i = 0; i < KYBER_N; i++) {
        // Here we have the view of the attacker, who knows the message bits
        if (get_message_bit(global__message, i) == 1) continue;

        // All message bits = 0 will be considered as high or low weights, depending on the case

        int max_message_coeff_given_HW = 0;
        int min_message_coeff_given_HW = 0;

        // If high_case, consider every null index as having HW = HIGH_MIN
        if (high_case) {
            max_message_coeff_given_HW = MAX_NOISY_COEFF_FOR_SHARES_HWS[HIGH_MIN];
            min_message_coeff_given_HW = MIN_NOISY_COEFF_FOR_SHARES_HWS[HIGH_MIN];
        }

        // If high_case, consider every null index as having HW = LOW_MAX
        if (low_case) {
            max_message_coeff_given_HW = MAX_NOISY_COEFF_FOR_SHARES_HWS[LOW_MAX];
            min_message_coeff_given_HW = MIN_NOISY_COEFF_FOR_SHARES_HWS[LOW_MAX];
        }

        // The rest is the same as for the other attacks
        int16_t bias = global__e2.coeffs[i] + global__delta_v.coeffs[i];

        fprintf(stderr, "n_inequalities = %d\n", inequalities->n_inequalities_added);
        fprintf(stderr, "n_ciphertexts = %d\n", results->n_ciphertexts);
        fprintf(stderr, "n_wrong = %d\n", results->n_wrong_inequalities);
        for (int k = 0; k < 2; k++) {
            int n_ineq_added = inequalities->n_inequalities_added;
            if (inequalities->n_inequalities_added == params->n_inequalities)
                break;
            if (k == 0) {
                if (max_message_coeff_given_HW > MAX_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - max_message_coeff_given_HW - 1);
                inequalities->is_geq_zero.v[n_ineq_added] = 0;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   max_message_coeff_given_HW + 1);
                results->n_wrong_inequalities += is_wrong;
            }
            if (k == 1) {
                if (min_message_coeff_given_HW < MIN_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - min_message_coeff_given_HW);
                inequalities->is_geq_zero.v[n_ineq_added] = 1;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   min_message_coeff_given_HW);
                results->n_wrong_inequalities += is_wrong;
            }
        }
        if (inequalities->n_inequalities_added == params->n_inequalities)
            break;
    }
}

#else


#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

int get_min_in_cross(int share0_hw, int share1_hw) {

    int min = MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw];

    if (share0_hw > 0) min = MIN(min, MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw - 1][share1_hw]);
    if (share0_hw < 16) min = MIN(min, MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw + 1][share1_hw]);
    if (share1_hw > 0) min = MIN(min, MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw - 1]);
    if (share1_hw < 16) min = MIN(min, MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw + 1]);

    return min;
}

int get_max_in_cross(int share0_hw, int share1_hw) {

    int max = MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw];

    if (share0_hw > 0) max = MAX(max, MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw - 1][share1_hw]);
    if (share0_hw < 16) max = MAX(max, MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw + 1][share1_hw]);
    if (share1_hw > 0) max = MAX(max, MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw - 1]);
    if (share1_hw < 16) max = MAX(max, MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw + 1]);

    return max;
}

int get_av_min_in_cross(int share0_hw, int share1_hw) {

    int av = MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw];
    int n = 1;

    if (share0_hw > 0) {av += (MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw - 1][share1_hw]); n += 1;}
    if (share0_hw < 16) {av += (MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw + 1][share1_hw]); n += 1;}
    if (share1_hw > 0) {av += (MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw - 1]); n += 1;}
    if (share1_hw < 16) {av += (MIN_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw + 1]); n += 1;}

    return av / n;
}

int get_av_max_in_cross(int share0_hw, int share1_hw) {

    int av = MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw];
    int n = 1;

    if (share0_hw > 0) {av += (MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw - 1][share1_hw]); n += 1;}
    if (share0_hw < 16) {av += (MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw + 1][share1_hw]); n += 1;}
    if (share1_hw > 0) {av += (MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw - 1]); n += 1;}
    if (share1_hw < 16) {av += (MAX_NOISY_COEFF_FOR_SHARES_HWS[share0_hw][share1_hw + 1]); n += 1;}

    return av / n;
}


void get_noisy_sca_sample(attack_params_t *params, inequalities_data_t *inequalities,
                          results_t *results, int max_spread) {

    polyvec minus_e1_minus_delta_u = {0};
    get_minus_e1_minus_delta_u(&minus_e1_minus_delta_u, &global__e1, &global__delta_u);

    for (int i = 0; i < KYBER_N; i++) {
        if (get_message_bit(global__message, i) == 1) continue;

        int true_noisy_share0_coeff_hw = hamming_weight_int16(global__share0_noisy_message.coeffs[i]);
        int true_noisy_share1_coeff_hw = hamming_weight_int16(global__share1_noisy_message.coeffs[i]);

        int predicted_noisy_share0_coeff_hw = sample_predicted_from_true_value(params->confusion_matrix,
                                                                              true_noisy_share0_coeff_hw);

        int predicted_noisy_share1_coeff_hw = sample_predicted_from_true_value(params->confusion_matrix,
                                                                               true_noisy_share1_coeff_hw);

        int16_t bias = global__e2.coeffs[i] + global__delta_v.coeffs[i];


        int max_message_coeff_given_HW = MAX_NOISY_COEFF_FOR_SHARES_HWS[predicted_noisy_share0_coeff_hw][predicted_noisy_share1_coeff_hw];
        int min_message_coeff_given_HW = MIN_NOISY_COEFF_FOR_SHARES_HWS[predicted_noisy_share0_coeff_hw][predicted_noisy_share1_coeff_hw];

        // int max_message_coeff_given_HW = get_av_max_in_cross(predicted_noisy_share0_coeff_hw, predicted_noisy_share1_coeff_hw);
        // int min_message_coeff_given_HW = get_av_min_in_cross(predicted_noisy_share0_coeff_hw, predicted_noisy_share1_coeff_hw);

        int spread = (max_message_coeff_given_HW - min_message_coeff_given_HW);
        if (spread > max_spread)
            continue;

        fprintf(stderr, "n_wrong / n_inequalities = %d / %d\n", results->n_wrong_inequalities, inequalities->n_inequalities_added);
        fprintf(stderr, "n_ciphertexts = %d\n", results->n_ciphertexts);
        for (int k = 0; k < 2; k++) {
            int n_ineq_added = inequalities->n_inequalities_added;
            if (inequalities->n_inequalities_added == params->n_inequalities)
                break;

            if (k == 0) {
                if (max_message_coeff_given_HW > MAX_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - max_message_coeff_given_HW - 1);
                inequalities->is_geq_zero.v[n_ineq_added] = 0;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   max_message_coeff_given_HW + 1);
                results->n_wrong_inequalities += is_wrong;
            }
            if (k == 1) {
                if (min_message_coeff_given_HW < MIN_VALID_NOISY_COEFF) continue;
                inequalities->b.v[n_ineq_added] = mod_centered(bias - min_message_coeff_given_HW);
                inequalities->is_geq_zero.v[n_ineq_added] = 1;
                write_a_row_in_inequalities(inequalities, i, &minus_e1_minus_delta_u, &global__r);
                inequalities->n_inequalities_added += 1;

                int is_wrong = is_wrong_inequality(global__noisy_message.coeffs[i],
                                                   inequalities->is_geq_zero.v[n_ineq_added],
                                                   min_message_coeff_given_HW);
                results->n_wrong_inequalities += is_wrong;
            }
        }
        if (inequalities->n_inequalities_added == params->n_inequalities)
            break;

    }
}

#endif
