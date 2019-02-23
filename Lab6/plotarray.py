# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import matplotlib.pyplot as plt
import numpy as np
a = np.loadtxt('what.txt')
plt.plot(range(len(a)),a)