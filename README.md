nonce-calculator
================

A small filter calculating nonce for any blob of data

nonce-calculator reads data from standard input, calculates a nonce for this data and prints it to standard output.
If anything went wrong, the return value of the program should be non zero.

The number of CPUs used for the calculation is all CPUs found on the system - 1
