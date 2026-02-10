#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  libffi-dev \
  libfuzzy-dev

# If you ever see: fatal error: Python.h: No such file or directory
# sudo apt-get install -y python3-dev
