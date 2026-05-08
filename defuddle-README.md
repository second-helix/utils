# Defuddle

## Overview

This tool removes ANSI escape sequences, control characters, and corrupted Unicode from console output logs, making them human-readable.

## What It Removes

### 1. ANSI Escape Sequences (CSI)
- **Color codes**: `[38;2;255;193;7m`, `[39m`, `[1m`, `[22m`
- **Cursor movement**: `[H`, `[G`, `[1A`, `[4G`
- **Screen clearing**: `[2J`, `[3J`, `[2K`
- **Mode controls**: `[?2026h`, `[?25l`, `[?2004h`

### 2. OSC Sequences (Operating System Command)
- Pattern: `]9001;CmdNotFound;.claude\`, `]9;4;0;`, `]9;9;D:\`

### 3. Control Characters
- Carriage returns (`\r`) used for overwriting
- Other control characters (0x00-0x08, 0x0b-0x0c, 0x0e-0x1f, 0x7f)

### 4. Corrupted Unicode
- Multi-byte UTF-8 sequences from improperly decoded CP850 text
- Includes em dash, quotes, and other common corruption patterns

## Usage

### Clean a single file
```bash
python defuddle.py ConEmu-2026-01-04-p16716.log
```

### Clean all log files in directory
```bash
python defuddle.py -d . -p "*.log"
```

### Verbose mode
```bash
python defuddle.py ConEmu-2026-01-04-p16716.log -v
```

### Keep corrupted characters
```bash
python defuddle.py ConEmu-2026-01-04-p16716.log --keep-corrupted
```

### Specify output directory
```bash
python defuddle.py -d . -o cleaned_logs/
```

## Output

Cleaned files are saved with a `.clean` suffix:
- Input: `ConEmu-2026-01-04-p16716.log`
- Output: `ConEmu-2026-01-04-p16716.log.clean`

## Example Results

### Before (with ANSI codes)
```
[38;2;255;193;7mWelcome back![39m
D:\[0m ]9;9;D:\
```

### After (cleaned)
```
Welcome back!
D:\
```

## Features

- **Multiple encoding support**: Tries UTF-8, UTF-8-sig, Latin-1, CP1252, and CP850
- **Batch processing**: Clean multiple files at once
- **Flexible options**: Keep or remove corrupted characters as needed
- **Preserves newlines**: Maintains log structure
