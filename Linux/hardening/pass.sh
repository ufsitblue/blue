#!/bin/sh
if uname -a | grep BSD; then
  ./pass.bsd.sh
else
  ./pass.std.sh
fi
