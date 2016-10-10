#!/bin/bash
set -e

if [[ ! -d build/_doxygen ]]; then
    if [[ ! -f build/Makefile ]]; then
        ./run_cmake.sh build
    fi
    make -C doxygen
fi

xdg-open build/_doxygen/index.html
