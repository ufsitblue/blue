#!/bin/sh
if uname -a | grep BSD; then
  ./blackout.bsd.sh
else
  ./blackout.std.sh
fi
