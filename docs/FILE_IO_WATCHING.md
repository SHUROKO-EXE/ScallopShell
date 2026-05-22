# File I/O Watching

On the bottom right quadrant of the screen is the file I/O watching tab. Default output is both STDERR and STDOUT. Default input is stdin. 

## Controls

- Ctrl+F: Search for a file descriptor(s) to read from. Leaving it blank will set it back to default output. To have multiple read from, seperate your selections by spaces ( 1 2 10 40 )
- Ctrl+Alt+F: Search for a file descriptor(s) to write to. Leaving it blank will set it back to default output. To have multiple written to, seperate your selections by spaces ( 0 20 30 )
- Keyboard Input: Send input into the file descriptor(s) currently selected.