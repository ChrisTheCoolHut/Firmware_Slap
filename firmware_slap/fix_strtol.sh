#!/bin/bash
rm $VIRTUAL_ENV/lib/python3.5/site-packages/angr/procedures/libc/strtol.py
wget https://raw.githubusercontent.com/angr/angr/master/angr/procedures/libc/strtol.py -O $VIRTUAL_ENV/lib/python3.5/site-packages/angr/procedures/libc/strtol.py
