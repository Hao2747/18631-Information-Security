#!/bin/bash
socat tcp-listen:23555,reuseaddr,fork EXEC:'python3 pcks7.py' &
