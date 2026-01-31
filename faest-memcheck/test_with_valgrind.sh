#!/bin/bash

set -e # Exit immediately if any command exits with a non-zero status

cargo build --features valgrind
valgrind --tool=memcheck ../target/debug/faest-memcheck