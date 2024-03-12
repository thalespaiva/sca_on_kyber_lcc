import seaborn as sns
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import rc
from matplotlib import rcParams
import random
import os


LNCS_FIG_WIDTH = 5.3
LNCS_BIG_FIG_HEIGHT = 4
# LNCS_SMALL_FIG_HEIGHT = 2.5
LNCS_SMALL_FIG_HEIGHT = 2.0
# LNCS text width: 5.37502in

def latexify_lncs(fig_width=LNCS_FIG_WIDTH, fig_height=LNCS_SMALL_FIG_HEIGHT, small=False, fs=10):

    sns.reset_orig()

    rc('font', **{'family': 'serif', 'serif': ['Computer Modern']})
    rc('text', usetex=True)
    rcParams['font.size'] = fs
    from math import sqrt

    if fig_width is None:
        fig_width = 4.8  # approx 12.2 cm

    if fig_height is None:
        golden_mean = (sqrt(5) - 1.0) / 2.0  # Aesthetic ratio
        fig_height = fig_width * golden_mean  # height in inches

    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large:" + fig_height +
              "so will reduce to" + MAX_HEIGHT_INCHES + "inches.")
        fig_height = MAX_HEIGHT_INCHES

    ticksize = 8
    if small:
        ticksize = 7

    params = {
        'backend': 'pdf',
        'axes.labelsize': fs,  # fontsize for x and y labels (was 10)
        'axes.titlesize': fs,
        'font.size': fs,  # was 10
        'legend.fontsize': 8,  # was 10
        'font.family': 'serif',
        'xtick.labelsize': ticksize,
        'xtick.labelsize': ticksize,
        'ytick.labelsize': ticksize,
        'lines.linewidth': 0.5,
        'lines.markersize': 4.5,
        'lines.markeredgewidth': 0.1,
        'ytick.major.width': 0.5,
        'ytick.minor.width': 0.5,
        'xtick.major.width': 0.5,
        'xtick.minor.width': 0.5,
        'text.usetex': True,
        'axes.edgecolor': 'black',
        'legend.edgecolor': 'black',
        'legend.frameon': False,
        'axes.linewidth': 0.5,
        'axes.linewidth': 0.5,
        'axes.spines.bottom': True,
        'axes.spines.left': True,
        'axes.spines.right': False,
        'axes.spines.top': False,
        'figure.figsize': [fig_width, fig_height],
    }

    rcParams.update(params)


def plot_solver_comparison(dirpath='../results/solver_comparison'):

    AO = 'OASM'
    FILES = {
        'O0': os.path.join(dirpath, 'conf_matrix_1_acc_0.97036_o0_merged.csv'), 
        'O3': os.path.join(dirpath, 'conf_matrix_2_acc_0.74092_o3_merged.csv'),
        AO: os.path.join(dirpath, 'conf_matrix_0_acc_0.3708_opt_merged.csv'), 
    }

    GS = 'Greedy Search'
    BP = 'Belief Propagation'

    plt.figure()

    style = {
        ('O0', GS): {'c': 'k', 'ls': '-', 'marker':'o', 'mew': 0},
        ('O3', GS): {'c': 'k', 'ls': '-', 'marker':'^', 'mew': 0},
        (AO, GS): {'c': 'k', 'ls': '-', 'marker':'P', 'mew': 0},
        ('O0', BP): {'c': '0.5', 'ls': '-', 'marker':'o', 'mew': 0},
        ('O3', BP): {'c': '0.5', 'ls': '-', 'marker':'^', 'mew': 0},
        (AO, BP): {'c': '0.5', 'ls': '-', 'marker':'P', 'mew': 0},
    }

    for alg in [GS, BP]:
        for opt, f in FILES.items():
            df = pd.read_csv(f)
            sns.lineplot(data=df[df.algorithm == alg], 
                         x='n_inequalities', 
                         y='fraction_of_solution_recovered',
                         label=f'{alg} ({opt})',
                         **style[opt, alg],
                         err_style=None)
        # plt.title(f)

    plt.xlabel('Number of inequalities')
    # plt.ylabel(r'Fraction of sulution $(\mathbb{e}, \mathbb{s})$ recovered'))
    plt.ylabel(r'Fraction of solution recovered')
    plt.tight_layout()

    plt.savefig('../figs/solver_comparison/solver_comparison.pdf')


def plot_n_ciphertexts_needed(data='../results/n_ciphertexts_needed/n_ciphertexts_needed.csv'):
    full_df = pd.read_csv(data)
    results = {}

    data_points = {
        'algorithm': [],
        'scale': [],
        'seed': [],
        'number_of_ciphertexts': [],
    }
    for sel, d in full_df[full_df.recovered_key == True].groupby(['algorithm', 'scale', 'seed']):
        print(sel, min(d.approx_number_of_ciphertexts))
        algorithm, scale, seed = sel
        data_points['algorithm'].append(algorithm)
        data_points['scale'].append(scale)
        data_points['seed'].append(seed)
        data_points['number_of_ciphertexts'].append(min(d.approx_number_of_ciphertexts))

    df = pd.DataFrame.from_dict(data_points)
    print(df)

    BP = 'Belief Propagation'
    GS = 'Greedy Search'
    style = {
        BP: {'c': 'k', 'ls': '--', 'marker':'.', 'mew': 0},
        GS: {'c': 'k', 'ls': '-', 'marker':'*', 'mew': 0},
    }

    for algorithm in [BP, GS]:
        sns.lineplot(data=df[df.algorithm == algorithm], x='scale', y='number_of_ciphertexts',
                     label=algorithm, **style[algorithm])
    plt.xlabel('Standard deviation of simulated Gaussian SCA error')
    plt.ylabel('Number of ciphertexts')
    plt.xticks(np.arange(0, 2.01, 0.2))
    plt.yticks(np.arange(0, 1300, 250))
    plt.xlim(0, 2)
    plt.ylim(0, 1300)
    plt.legend(loc='lower right')
    plt.tight_layout()

    # plt.savefig('figs/number_of_ciphertext_neeed_masked.pdf')


def plot_n_ciphertexts_needed_masked(data='../results/n_ciphertexts_needed/n_ciphertexts_masked.csv'):
    full_df = pd.read_csv(data)
    results = {}

    data_points = {
        'algorithm': [],
        'scale': [],
        'seed': [],
        'number_of_ciphertexts': [],
    }
    for sel, d in full_df[full_df.recovered_key == True].groupby(['algorithm', 'scale', 'seed']):
        print(sel, min(d.approx_number_of_ciphertexts))
        algorithm, scale, seed = sel
        data_points['algorithm'].append(algorithm)
        data_points['scale'].append(scale)
        data_points['seed'].append(seed)
        data_points['number_of_ciphertexts'].append(min(d.approx_number_of_ciphertexts))

    df = pd.DataFrame.from_dict(data_points)
    print(df)

    BP = 'Belief Propagation'
    GS = 'Greedy Search'
    style = {
        BP: {'c': 'k', 'ls': '--', 'marker':'.', 'mew': 0},
        GS: {'c': 'k', 'ls': '-', 'marker':'*', 'mew': 0},
    }

    for algorithm in [BP, GS]:
        sns.lineplot(data=df[df.algorithm == algorithm], x='scale', y='number_of_ciphertexts',
                     label=algorithm, **style[algorithm])
    plt.xlabel('Standard deviation of simulated Gaussian SCA error')
    plt.ylabel('Number of ciphertexts')
    plt.xticks(np.arange(0, 0.71, 0.1))
    plt.yticks(np.arange(0, 800001, 200000))
    plt.xlim(0, 0.7)
    plt.ylim(0, 800000)
    plt.legend(loc='lower right')
    plt.tight_layout()

    # plt.savefig('figs/number_of_ciphertext_neeed_masked.pdf')









