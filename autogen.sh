#!/bin/sh
#
# autogen.sh
#
# Create configure and makfile stuff...
#

# Git hooks must be setup before autoreconf
if [ -d .git ]; then
  if [ ! -d .git/hooks ]; then
    mkdir .git/hooks
  fi
  ln -s -f ../../pre-commit.sh .git/hooks/pre-commit
fi

autoreconf --install --force --verbose

