base_seed = 100000


scales = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0]

n_total_inequalities = 1000000

for i in range(5):
    for j, sd in enumerate(scales):
        seed = base_seed + j*100 + i
        str_sd = '%.2f' % sd
        confusion_matrix = f'../../data/gaussian_confusion_matrices/scale_{str_sd}.csv'
        print(f'./find_n_ciphertexts_needed_masked {seed} {n_total_inequalities} {confusion_matrix} > tmp_n_ciphertexts_masked/sd{str_sd}_seed{seed}.csv 2> /dev/null')
        seed += 1

# Use resulting file with:
# $ mkdir tmp_n_ciphertexts_masked; cat resulting_file | xargs --max-procs 40 -I cmd bash -c "cmd" &