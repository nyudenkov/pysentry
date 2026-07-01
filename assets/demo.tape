# PySentry README demo. Source-of-truth for assets/demo.gif — edit this, not the GIF.
# Regenerate (vhs leaks the hidden setup into the first ~5 frames; gifsicle drops
# them and compresses):
#   vhs assets/demo.tape
#   gifsicle --unoptimize assets/demo.gif --delete "#0-4" -O3 --lossy=30 -o /tmp/d.gif && mv /tmp/d.gif assets/demo.gif

Output assets/demo.gif

Set Shell "zsh"
Set FontFamily "Monaspace Neon"
Set FontSize 16
Set Width 1000
Set Height 620
Set Padding 22
Set Margin 30
Set MarginFill "#11111b"
Set BorderRadius 12
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

# Off-camera: warm the uvx cache and wrap `uvx` so its output streams line by
# line (scrolling effect) with colors forced on through the pipe. The recorded
# command stays clean: `uvx pysentry-rs . --compact`.
Hide
Type "cd $HOME/Work/open-source/saleor"
Enter
Type 'uvx() { command uvx "$@" --color always 2>&1 | while IFS= read -r l; do print -r -- "$l"; if [[ $l == *SEVERITY* ]]; then sleep 1.3; else sleep 0.05; fi; done }'
Enter
Type "uvx pysentry-rs . --compact >/dev/null 2>&1"
Enter
Sleep 4s
# Full terminal reset (RIS) wipes scrollback too; plain `clear` leaves the
# setup text in the buffer and it leaks into the first captured frame.
Type 'printf "\033c"'
Enter
Sleep 600ms
Show

Sleep 700ms
Type "uvx pysentry-rs . --compact"
Sleep 800ms
Enter
# ~1s compute, then the report scrolls past; hold briefly on the tail.
Sleep 6s
Sleep 2s
