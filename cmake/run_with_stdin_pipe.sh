#!/bin/sh

# Expected Parameters:
# $1 program to run
# $2 file which should be piped into stdin

exec "$1" < "$2"
