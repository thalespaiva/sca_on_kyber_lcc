# SPREADS = {0, 255, 297, 308, 317, 572, 577, 584, 586, 589, 592, 601, 630, 676};
# Use with: mkdir tmp_spread_results; cat thisfile | xargs --max-procs 10 -I cmd bash -c "cmd" &
./kyber_sca_full_attack_grid 10 1 0 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_0.csv
./kyber_sca_full_attack_grid 10 2 255 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_255.csv
./kyber_sca_full_attack_grid 10 3 297 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_297.csv
./kyber_sca_full_attack_grid 10 4 308 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_308.csv
./kyber_sca_full_attack_grid 10 5 317 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_317.csv
./kyber_sca_full_attack_grid 10 6 572 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_572.csv
./kyber_sca_full_attack_grid 10 7 577 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_577.csv
./kyber_sca_full_attack_grid 10 8 584 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_584.csv
./kyber_sca_full_attack_grid 10 9 586 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_586.csv
./kyber_sca_full_attack_grid 10 10 589 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_589.csv
./kyber_sca_full_attack_grid 10 11 592 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_592.csv
./kyber_sca_full_attack_grid 10 12 601 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_601.csv
./kyber_sca_full_attack_grid 10 13 630 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_630.csv
./kyber_sca_full_attack_grid 10 14 676 ../../data/gaussian_confusion_matrices/scale_0.csv 2> /dev/null > tmp_spread_results/spread_676.csv
