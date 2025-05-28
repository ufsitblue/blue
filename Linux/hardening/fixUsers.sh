#!/bin/sh
if uname -a | grep BSD; then
  ./fixUsers.bsd.sh
else
  ./fixUsers.std.sh
fi
