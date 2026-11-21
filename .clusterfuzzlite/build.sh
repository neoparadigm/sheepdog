#!/bin/bash -eu
# Builds the Atheris target for ClusterFuzzLite.
pip3 install .
pip3 install pytest hypothesis   # tests.helpers is imported by the target
compile_python_fuzzer fuzz/fuzz_policy.py
