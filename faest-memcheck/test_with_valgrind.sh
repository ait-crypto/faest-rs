#!/bin/bash

set -e # Exit immediately if any command exits with a non-zero status

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

helpFunction()
{
  echo ""
  echo "Usage: test_with_valgrind.sh [--opt-simd] -h"
  echo -e "\t--opt-simd Tests optimized simd implementation (if supported by target architecture)"
  echo -e "\t-h Print the script help message."
  exit 1
}

for arg in "$@"; do
   case "$arg" in
      --opt-simd )
        opt_simd=true ;;
      h ) helpFunction ;;
      ? ) helpFunction ;;
      *)
        helpFunction 
        exit 1 ;;
   esac
done

if [[ -v opt_simd ]] ; then
    echo "Testing avx2 implementation..."
    RUSTFLAGS="-C target-cpu=native" cargo build --all-features
else
    echo "Testing unoptimized implementation..."
    cargo build --no-default-features --features valgrind,std,randomized-signer
fi
valgrind --tool=memcheck --error-exitcode=1 $SCRIPT_DIR/../target/debug/faest-memcheck 
echo "Done."
