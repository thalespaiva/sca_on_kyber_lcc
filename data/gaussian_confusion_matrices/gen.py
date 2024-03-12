import numpy as np
from scipy.stats import norm

MAX_HW = 16

def generate_row(center, scale):
    values = [norm.cdf(0.5, loc=center, scale=scale)]
    for i in range(1, MAX_HW):
        values.append(norm.cdf(i + 0.5, loc=center, scale=scale) - norm.cdf(i - 0.5, loc=center, scale=scale))
    values.append(1 - norm.cdf(16 - 0.5, loc=center, scale=scale))

    return values


def generate_confusion_matrix(scale):
    if scale == 0:
        return np.identity(MAX_HW + 1, dtype=np.int16)
    return [generate_row(i, scale) for i in range(MAX_HW + 1)]


if __name__ == '__main__':
    for scale in np.arange(0, 2.01, 0.1):
        cm = generate_confusion_matrix(scale)

        f = open(f'scale_%0.2f.csv' % round(scale, 1), 'w')
        print('#', file=f)
        for row in cm:
            for value in row:
                print('%.4f ' % value, file=f, end='')
            print(file=f)
        f.close()
