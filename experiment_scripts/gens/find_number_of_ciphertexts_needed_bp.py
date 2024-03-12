base_seed = 100000


scales = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

n_total_inequalities = 150000

for j, sd in enumerate(scales):
    for i in range(5):
        seed = base_seed + j*100 + i
        str_sd = '%.2f' % sd
        confusion_matrix = f'../data/gaussian_confusion_matrices/scale_{str_sd}.csv'
        print(f'python3 test_bp_solver.py {seed} {n_total_inequalities} {confusion_matrix} > tmp_n_ciphertexts_belief_propagation/sd{str_sd}_seed{seed}.csv 2> /dev/null')
        seed += 1

# Use resulting file with:
# $ mkdir tmp_n_ciphertexts_belief_propagation; cat resulting_file | xargs --max-procs 40 -I cmd bash -c "cmd" &