# should compare the 3 different techniques among all the different firewall schemes

# make table for one of the firewalls


import math
import random
import matplotlib.pyplot as plt
import numpy as np

# values chosen are mean if low std dev (less than 1.8e-06) and median otherwise
# then plot graph of errors from iterative method
# can plot processing speeds based on pkthdrs too
convert = 58/1000000
dispersion = ((1/1.6850964737192286e-05)*convert, (1/1.2265401265401264e-05)*convert, (1/1.2e-05)*convert, (1/1.373205200678349e-05)*convert, (1/1.2e-05)*convert)
iterative = (55465*convert, 75208*convert, 80406*convert, 75359*convert, 77433*convert)
flooding = ((1/1.769652563377832e-05)*convert, (1/1.3e-05)*convert, (1/1.0577031786754795e-05)*convert, (1/1.3e-05)*convert, (1/1.2874244466669561e-05)*convert)
flooding_opt = (55299*convert, 75018*convert, 81555*convert, 71495*convert, 76870*convert)
firewalls = ("Blacklist", "Blacklist-M", "Tor","Deleted", "Malware")
processing_means = {
    "Dispersion": dispersion,
    "Iterative": iterative,
    "Flooding": flooding,
    "Flooding-Opt": flooding_opt, 
}
x = []
y = []


"""for i in range(len(x)):
  y_mean[i] = abs(y_mean[i] - x[i])
  y_mean[i] /= x[i] 
  y_median[i] = abs(y_median[i] - x[i])
  y_median[i] /= x[i] """

x = np.arange(len(firewalls))  # the label locations
width = 0.1  # the width of the bars
multiplier = 0

fig, ax = plt.subplots()

for attribute, measurement in processing_means.items():
    offset = width * multiplier
    print(x + offset)
    rects = ax.bar(x + offset, measurement, width, label=attribute)
    #ax.bar_label(rects, padding=0)
    multiplier += 1

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel("Processing speed (Mbs/sec)")
ax.set_xlabel("Firewall")
ax.set_title("Measuring Techniques on different Firewalls")
ax.set_xticks(x + width, firewalls)
ax.legend(loc="upper left")





# plt.plot(x, y_mean, label = "mean", marker = 'o')
# plt.plot(x, y_median, label = "median", marker = 'o')


plt.grid(axis = 'y')
ax.grid(axis = 'y')
plt.show()
