# LEDBAT-Plus-Plus

Linux kernel module of LEDBAT++ (Conforming to draft version 01)

It compiled successfully on Linux kernels 5.19.0 and 6.10.0.

This is the LEDBAT++ source code used to produce the results presented in "TCP FlexiS: A New Approach to Incipient Congestion Detection and Control".
DOI: 10.1109/TNET.2023.3319441

If you want to use this source code to produce results to be used in your own publications, please kindly reference this GITHUB webpage or the above paper whichever you feel more appropriate.

How to use
    Download the source code (tcp_ledbatpp.c and Makefile) into a directory, e.g. ledbatpp
    Under the directory "ledbatpp" issue the following commands 
    make
    sudo make install
    The kernel module tcp_ledbatpp should be installed and loaded after these steps.
    Verify with lsmod | grep ledbatpp
