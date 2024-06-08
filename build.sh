#!/bin/sh

set -xe

cc -Wall -Wextra -pedantic -rdynamic -pipe -ggdb -std=c89 -o main main.c -lssl
