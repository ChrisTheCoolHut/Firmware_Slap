#!/bin/bash

# Make sure ghidra's  analyzeHeadless is on the path

echo "Analyzing "  $1

#If there is already a project
# analyzeHeadless . Project_test -process ssi -scriptPath ./ -noanalysis -max-cpu 1 -preScript SetDecompilerOptions.py -postScript DumpFunctions.py "./output_file"

which analyzeHeadless || echo "Ghidra analyzeHeadless not on PATH. Please add to path" || exit 1

analyzeHeadless . Project_test -import $1 -scriptPath ./ -preScript SetDecompilerOptions.py -postScript DumpFunctions.py "./Output_File"
rm -rf Project_test*
