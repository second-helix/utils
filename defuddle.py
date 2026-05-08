#!/usr/bin/env python3
"""
defuddle
Removes ANSI escape sequences, OSC sequences, and other control characters
from console output logs, leaving only human-readable text.
"""

import argparse
import codecs
import re
import sys
from pathlib import Path


class Defuddle:
    """Cleaner for ConEmu console log files."""
    
    # ANSI escape sequences patterns
    CSI_PATTERN = r'\x1b\[[0-?]*[ -/]*[@-~]'
    OSC_PATTERN = r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'
    
    # Combined pattern for all escape sequences
    ALL_ESCAPES = r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'
    
    # Fallback order matters because single-byte codecs decode any byte stream.
    FALLBACK_ENCODINGS = ('cp1252', 'cp850', 'latin-1')
    
    # Corrupted CP850/UTF-8 box-drawing characters (remove or replace)
    # These are common corrupted sequences from CP850 decoded as UTF-8
    CORRUPTED_CHARS = [
        '\xe2\x80\x94',  # em dash
        '\xe2\x80\x9c',  # left double quote
        '\xe2\x80\x9d',  # right double quote
        '\xe2\x80\xa0',  # dagger
        '\xe2\x80\xa1',  # double dagger
        '\xe2\x80\xb0',  # per mille sign
        '\xe2\x80\xb9',  # single left-pointing angle quotation mark
        '\xe2\x80\xba',  # single right-pointing angle quotation mark
        '\xc2\xa0',      # non-breaking space
        '\xc2\xa2',      # cent sign
        '\xc2\xa3',      # pound sign
        '\xc2\xa7',      # section sign
        '\xc2\xa8',      # diaeresis
        '\xc2\xb0',      # degree symbol
        '\xc2\xb1',      # plus-minus
        '\xc2\xb6',      # pilcrow
        '\xc3\x98',      # O with stroke
        '\xc5\xa1',      # s with caron
    ]
    
    def __init__(self, remove_corrupted=True, keep_newlines=True, verbose=False):
        """
        Initialize the cleaner.
        
        Args:
            remove_corrupted: If True, remove corrupted unicode characters
            keep_newlines: If True, preserve newlines in output
            verbose: If True, print detailed processing information
        """
        self.remove_corrupted = remove_corrupted
        self.keep_newlines = keep_newlines
        self.verbose = verbose
        
        # Compile regex patterns
        self.ansi_re = re.compile(self.ALL_ESCAPES, re.MULTILINE)
        self.control_chars_re = re.compile(
            r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]'  # All control chars except \t, \n, \r
        )

    def _score_fallback_decoding(self, text):
        """Prefer decodings with fewer obvious mojibake/control artifacts."""
        score = 0

        # Latin-1 often surfaces C1 controls where CP1252 would yield punctuation.
        score += sum(1 for char in text if '\x80' <= char <= '\x9f') * 100

        for fragment in self.CORRUPTED_CHARS:
            score += text.count(fragment) * 25

        return score

    def _read_content(self, input_path):
        """Read file bytes and decode with a deterministic fallback strategy."""
        input_bytes = input_path.read_bytes()

        if input_bytes.startswith(codecs.BOM_UTF8):
            return input_bytes.decode('utf-8-sig'), 'utf-8-sig'

        try:
            return input_bytes.decode('utf-8'), 'utf-8'
        except UnicodeDecodeError:
            pass

        best_text = None
        best_encoding = None
        best_score = None

        for priority, encoding in enumerate(self.FALLBACK_ENCODINGS):
            text = input_bytes.decode(encoding)
            candidate_score = (self._score_fallback_decoding(text), priority)

            if best_score is None or candidate_score < best_score:
                best_text = text
                best_encoding = encoding
                best_score = candidate_score

        if best_text is None:
            raise UnicodeError('Could not decode file with supported encodings')

        return best_text, best_encoding

    @staticmethod
    def _keep_last_overwrite(line):
        """Keep the most recent visible segment when carriage returns rewrite a line."""
        if '\r' not in line:
            return line

        segments = line.split('\r')

        for segment in reversed(segments):
            if segment:
                return segment

        return ''
    
    def clean_line(self, line):
        """
        Clean a single line of text.
        
        Args:
            line: String to clean
            
        Returns:
            Cleaned string
        """
        # Remove all ANSI escape sequences (CSI and OSC)
        line = self.ansi_re.sub('', line)
        
        # Keep the most recent content when \r is used to refresh a line.
        line = self._keep_last_overwrite(line)
        
        # Remove standalone \r characters (but preserve newlines)
        line = line.replace('\r', ' ')
        
        # Remove other control characters (but keep \n and \t)
        line = self.control_chars_re.sub(' ', line)
        
        # Remove corrupted unicode if requested
        if self.remove_corrupted:
            for char in self.CORRUPTED_CHARS:
                line = line.replace(char, '')
        
        # Clean up multiple spaces
        line = re.sub(r' +', ' ', line)
        
        # Clean up leading/trailing whitespace
        line = line.strip()
        
        return line
    
    def clean_file(self, input_path, output_path=None):
        """
        Clean a ConEmu log file.
        
        Args:
            input_path: Path to input log file
            output_path: Path to output file (default: input path with .clean extension)
            
        Returns:
            Number of lines processed
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Determine output path
        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.clean')
        else:
            output_path = Path(output_path)
        
        if self.verbose:
            print(f"Processing: {input_path}")
            print(f"Output: {output_path}")
        
        lines_processed = 0
        lines_output = 0
        
        content, used_encoding = self._read_content(input_path)
        if self.verbose:
            print(f"Successfully read with encoding: {used_encoding}")
        
        # Clean the content line by line
        with open(output_path, 'w', encoding='utf-8') as f:
            for line in content.split('\n'):
                lines_processed += 1
                
                cleaned_line = self.clean_line(line)
                
                # Skip empty lines if they don't contain meaningful content
                if cleaned_line:
                    f.write(cleaned_line + '\n')
                    lines_output += 1
                elif self.keep_newlines:
                    # Preserve line structure for empty lines
                    f.write('\n')
        
        if self.verbose:
            print(f"Processed {lines_processed} lines")
            print(f"Output {lines_output} non-empty lines")
        
        return lines_output
    
    def batch_clean(self, input_dir, pattern='*.log', output_dir=None):
        """
        Clean multiple log files in a directory.
        
        Args:
            input_dir: Directory containing log files
            pattern: Glob pattern to match files (default: *.log)
            output_dir: Directory for output files (default: same as input with .clean suffix)
            
        Returns:
            Dictionary of file paths and lines processed
        """
        input_dir = Path(input_dir)
        
        if not input_dir.is_dir():
            raise NotADirectoryError(f"Not a directory: {input_dir}")
        
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        for input_file in sorted(input_dir.glob(pattern)):
            if output_dir:
                output_file = output_dir / (input_file.name + '.clean')
            else:
                output_file = None
            
            try:
                lines = self.clean_file(input_file, output_file)
                results[input_file] = lines
            except Exception as e:
                if self.verbose:
                    print(f"Error processing {input_file}: {e}")
                results[input_file] = None
        
        return results


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description='Clean console log files by removing ANSI escape sequences',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Clean a single log file
  python defuddle.py ConEmu-2026-01-04-p16716.log
  
  # Clean all log files in current directory
  python defuddle.py -d . -p "*.log"
  
  # Clean with verbose output and keep corrupted characters
  python defuddle.py ConEmu-2026-01-04-p16716.log -v --keep-corrupted
  
  # Specify output directory
  python defuddle.py -d . -o cleaned_logs/
        """
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        help='Input log file path (if not specified, use -d to process a directory)'
    )
    
    parser.add_argument(
        '-d', '--directory',
        help='Directory containing log files to process'
    )
    
    parser.add_argument(
        '-p', '--pattern',
        default='*.log',
        help='Glob pattern for files to process (default: *.log)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file or directory path'
    )
    
    parser.add_argument(
        '--keep-corrupted',
        action='store_true',
        help='Keep corrupted unicode characters instead of removing them'
    )
    
    parser.add_argument(
        '--no-newlines',
        action='store_true',
        help='Don\'t preserve empty lines in output'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Print detailed processing information'
    )
    
    args = parser.parse_args()
    
    # Create cleaner
    cleaner = Defuddle(
        remove_corrupted=not args.keep_corrupted,
        keep_newlines=not args.no_newlines,
        verbose=args.verbose
    )
    
    try:
        if args.directory:
            # Process directory
            results = cleaner.batch_clean(args.directory, args.pattern, args.output)
            
            if results:
                had_errors = False
                print(f"\nProcessed {len(results)} file(s):")
                for input_file, lines in results.items():
                    if lines is not None:
                        print(f"  OK {input_file.name}: {lines} lines")
                    else:
                        print(f"  ERROR {input_file.name}: failed")
                        had_errors = True

                if had_errors:
                    sys.exit(1)
        elif args.input_file:
            # Process single file
            lines = cleaner.clean_file(args.input_file, args.output)
            print(f"\nOK Cleaned: {lines} lines output")
        else:
            parser.print_help()
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
