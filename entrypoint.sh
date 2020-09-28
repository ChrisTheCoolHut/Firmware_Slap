#!/bin/bash
set -x
set -e
export PATH=$PATH:/fwslap/bin:/ghidra/ghidra_9.0.4/support/
alias python="/usr/bin/python3"
exec "$@"