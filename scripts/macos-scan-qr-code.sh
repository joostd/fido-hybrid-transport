#!/bin/sh

# scan the QR code in the last image containing a QR code created using the macOS screenshot tool (CMD-SHIFT-4 + SPACE + click)
# uses zbarimg (brew install zbar)

set -o pipefail

command -v zbarimg > /dev/null || { echo "install zbarimg first (brew install zbar)"; exit -1; }

file=$(ls -tr ~/Desktop/Screenshot\ ????-??-??\ at\ ??.??.??*.png | tail -1)
echo $file

#ls -tr ~/Desktop/Screenshot\ ????-??-??\ at\ ??.??.??*.png | tail -1 | xargs -I{} zbarimg -q --raw "{}" | pbcopy || { echo no QR code found in screenshot; exit -1; }
zbarimg -q --raw "$file" | pbcopy || { echo no QR code found in screenshot; exit -1; }

echo Decoded QR code copied to pastboard, continue with:
echo uv run main.py $(pbpaste)
rm -i "$file"
