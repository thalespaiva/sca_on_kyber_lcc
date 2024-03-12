cmake_minimum_required(VERSION 3.10.2)

project(kyber_sca_simulation)

set(CMAKE_C_COMPILER gcc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wno-array-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-qual -Wunused-result")

set(KYBER_SCA_SRC   kyber768/aes256ctr.c kyber768/cbd.c kyber768/fips202.c kyber768/kem.c
                    kyber768/ntt.c kyber768/poly.c kyber768/polyvec.c
                    kyber768/reduce.c kyber768/rng.c kyber768/sha256.c kyber768/sha512.c
                    kyber768/symmetric-aes.c kyber768/symmetric-shake.c
                    kyber768/verify.c
                    # File kyber768/indcpa.c is 'overwritten' by sca_indcpa.c
                    sca_indcpa.c)

include_directories("kyber768")


add_library(sca_attack_simulation ${KYBER_SCA_SRC} sca_attack_simulation.c solver.c)
target_link_libraries(sca_attack_simulation crypto m)

# Attack using masked implementation
add_library(sca_attack_simulation_masked ${KYBER_SCA_SRC} sca_attack_simulation.c solver.c)
target_compile_definitions(sca_attack_simulation_masked PUBLIC SIMULATE_ATTACK_ON_MASKED_IMPLEMENTATION)
target_link_libraries(sca_attack_simulation_masked crypto m)

add_executable(kyber_sca_full_attack_masked kyber_sca_full_attack.c)
target_link_libraries(kyber_sca_full_attack_masked sca_attack_simulation_masked)


add_executable(kyber_sca_full_attack kyber_sca_full_attack.c)
target_link_libraries(kyber_sca_full_attack sca_attack_simulation)

add_executable(kyber_sca_full_attack_grid kyber_sca_full_attack_grid.c)
target_link_libraries(kyber_sca_full_attack_grid sca_attack_simulation)


# Attack using shuffled implementation
add_library(sca_attack_simulation_shuffled ${KYBER_SCA_SRC} sca_attack_simulation.c solver.c)
target_compile_definitions(sca_attack_simulation_shuffled PUBLIC SIMULATE_ATTACK_ON_SHUFFLED_IMPLEMENTATION)
target_link_libraries(sca_attack_simulation_shuffled crypto m)

add_executable(kyber_sca_full_attack_shuffled kyber_sca_full_attack.c)
target_link_libraries(kyber_sca_full_attack_shuffled sca_attack_simulation_shuffled)

########################################
#
# Executables to find number of ciphertexts needed for successful attack
#

add_executable(find_n_ciphertexts_needed find_n_ciphertexts_needed_to_attack.c)
target_link_libraries(find_n_ciphertexts_needed sca_attack_simulation)

add_executable(find_n_ciphertexts_needed_masked find_n_ciphertexts_needed_to_attack.c)
target_link_libraries(find_n_ciphertexts_needed_masked sca_attack_simulation_masked)


########################################
#
# Executables to build bias MIN-MAX matrices
#

add_executable(build_bias_matrices build_bias_matrices.c)
target_link_libraries(build_bias_matrices sca_attack_simulation)

add_executable(build_bias_matrices_masked build_bias_matrices.c)
target_link_libraries(build_bias_matrices_masked sca_attack_simulation_masked)


########################################
#
# Executables for comparing our solver with the belief propagation solver
#

add_executable(kyber_sca_generate_inequalities
               kyber_sca_generate_inequalities.c)
target_link_libraries(kyber_sca_generate_inequalities sca_attack_simulation)

add_executable(kyber_sca_solve_inequalities
               kyber_sca_solve_inequalities.c)
target_link_libraries(kyber_sca_solve_inequalities sca_attack_simulation)

###########
