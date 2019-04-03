#!/bin/bash

echo "gcc -o test test.c"
gcc -o test test.c
time ./test


echo ""
echo ""
echo "gcc -O3 -o test test.c"
gcc -O3 -o test test.c
time ./test

echo ""
echo ""
echo "time luajit test.lua"
time luajit test.lua

echo ""
echo ""
echo "time lua5.1 test.lua"
time lua5.1 test.lua

rm test
