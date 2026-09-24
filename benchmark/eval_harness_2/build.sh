#!/bin/bash
set -e

PLUGIN="/home/user/dev/ensia/build/obfuscation/libEnsia.so"

echo "Compiling baseline to IR..."
clang -O0 -emit-llvm -S test.c -o test_baseline.ll
clang -O0 test_baseline.ll -o test_baseline

# Obfuscate Function
obfuscate() {
    pass_flag=$1
    out_name=$2
    echo "Running pass $pass_flag..."
    opt -load-pass-plugin=${PLUGIN} ${pass_flag} -passes='ensia' test_baseline.ll -S -o ${out_name}.ll
    clang -O0 ${out_name}.ll -o ${out_name}
}

obfuscate "-enable-bcfobf" "test_bcf"
obfuscate "-enable-cffobf" "test_cff"
obfuscate "-enable-subobf" "test_sub"
obfuscate "-enable-mbaobf" "test_mba"
obfuscate "-enable-strcry" "test_str"
obfuscate "-enable-allobf" "test_all"

echo "Compilation done. Running tests..."
./test_baseline 42 > out_baseline.txt
./test_bcf 42 > out_bcf.txt
./test_cff 42 > out_cff.txt
./test_sub 42 > out_sub.txt
./test_mba 42 > out_mba.txt
./test_str 42 > out_str.txt
./test_all 42 > out_all.txt

echo "Diffing outputs with baseline..."
diff out_baseline.txt out_bcf.txt || echo "BCF differs"
diff out_baseline.txt out_cff.txt || echo "CFF differs"
diff out_baseline.txt out_sub.txt || echo "SUB differs"
diff out_baseline.txt out_mba.txt || echo "MBA differs"
diff out_baseline.txt out_str.txt || echo "STR differs"
diff out_baseline.txt out_all.txt || echo "ALL differs"

echo "Checking optimization stripping with opt (-O3)..."
opt -passes='default<O3>' -S test_cff.ll -o test_cff_opt.ll
opt -passes='default<O3>' -S test_bcf.ll -o test_bcf_opt.ll
opt -passes='default<O3>' -S test_sub.ll -o test_sub_opt.ll
opt -passes='default<O3>' -S test_mba.ll -o test_mba_opt.ll
opt -passes='default<O3>' -S test_all.ll -o test_all_opt.ll

echo "Checking overhead/bloat..."
wc -l test_baseline.ll test_*.ll | grep -v total

echo "Done."
