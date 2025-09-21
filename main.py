
# -*- coding: utf-8 -*-
import re
import sys
import base64
import os
import time
import random
import zlib
import traceback
import json
import argparse
from collections import OrderedDict
from colorama import init, Fore, Style
from pathlib import Path

init(autoreset=True)

BANNER = fr"""{Fore.RED}
       _                   _____           _
      | |                 / ____|         | |
      | | __ ___   ____ _| (___   ___ __ _| |_ ___  _ __
  _   | |/ _` \ \ / / _` |\___ \ / __/ _` | __/ _ \| '__|
 | |__| | (_| |\ V / (_| |____) | (_| (_| | || (_) | |
  \____/ \__,_| \_/ \__,_|_____/ \___\__,_|\__\___/|_|
{Fore.CYAN}=== JavaScator v2.0 ==={Style.RESET_ALL}"""

CONFIG_DIR = os.path.expanduser("JavaScator-Global/")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

RESERVED = {
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "export",
    "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new", "return", "super",
    "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with", "yield", "await", "enum", "null",
    "true", "false", "window", "document", "console", "Math", "JSON", "Date", "RegExp", "Array", "Object", "String",
    "Number", "Boolean", "Promise", "setTimeout", "setInterval", "clearTimeout", "clearInterval", "require",
    "module", "exports", "global", "eval", "arguments", "Infinity", "NaN", "undefined", "web3", "ethereum"
}

class Obfuscator:
    def __init__(self, level=3):
        self.level = level
        self.debug = False
        self.stats = {
            'renamed': 0, 'strings': 0, 'compressed': 0,
            'junk': 0, 'flattened': 0, 'hex_numbers': 0
        }
        self.start_time = time.time()
        self.original_code = ""
        self.config = self.load_config()
        self.name_generator = self.gen_names()

    def load_config(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load config: {e}{Style.RESET_ALL}")
        return {"default_level": 3}

    def save_config(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"{Fore.RED}Error saving config: {e}{Style.RESET_ALL}")

    def set_debug(self, debug):
        self.debug = debug

    def log(self, msg, color=Fore.YELLOW):
        if self.debug:
            elapsed = f"{time.time() - self.start_time:.3f}s"
            print(f"{color}[{elapsed}] [LEVEL {self.level}] {msg}{Style.RESET_ALL}")

    def extract_protected(self, code):
        self.log("Extracting protected sections...")
        placeholders, protected, idx = {}, [], 0
        token_re = re.compile(
            r'''("([^\\"]|\\.|\\\n)*")|('([^\\']|\\.|\\\n)*')|(`([^\\`]|\\.|\\\n)*`)|(//[^\n\r]*)|(/\*[\s\S]*?\*/)|(/\s*[^/*][^\\\n]*(?:\\.[^\\\n]*)*/[gimuy]*)''',
            re.MULTILINE
        )
        pos, out = 0, []
        for m in token_re.finditer(code):
            start, end = m.span()
            if pos < start:
                out.append(code[pos:start])
            token, key = m.group(0), f"__PROT_{idx}__"
            placeholders[key] = token
            out.append(key)
            idx += 1
            pos = end
        if pos < len(code):
            out.append(code[pos:])
        return "".join(out), placeholders

    def minify(self, code):
        self.log("Minifying code...")
        code = re.sub(r'[ \t]+', ' ', code)
        code = re.sub(r'\n\s*\n+', '\n', code)
        if self.level >= 2:
            code = re.sub(r'\s*([=+\-*/%<>!:;,{()\[\]}])\s*', r'\1', code)
        if self.level >= 4:
            code = re.sub(r';\s*;', ';', code)
        return code.strip()

    def find_decls(self, code):
        self.log("Finding declarations...")
        decls, seen = [], set(RESERVED)
        patterns = [
            (r'\b(var|let|const)\s+([^;]+);', lambda m: [x.strip().split('=')[0].split(',') for x in m.group(2).split(',')]),
            (r'\bfunction\b\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)', lambda m: [m.group(1)] + [x.strip() for x in m.group(2).split(',') if x.strip()]),
            (r'\b([A-Za-z_$][\w$]*)\s*=\s*\(([^)]*)\)\s*=>', lambda m: [x.strip() for x in m.group(2).split(',') if x.strip()]),
            (r'\bclass\s+([A-Za-z_$][\w$]*)', lambda m: [m.group(1)])
        ]
        for pattern, handler in patterns:
            for m in re.finditer(pattern, code):
                for name in sum(map(lambda x: [x] if isinstance(x, str) else x, handler(m)), []):
                    if name and name not in seen and re.match(r'^[A-Za-z_$][\w$]*$', name):
                        decls.append(name)
                        seen.add(name)
        return decls

    def gen_names(self):
        import string
        chars = string.ascii_letters + '_$'
        i = 0
        while True:
            s, n = "", i
            while True:
                s = chars[n % len(chars)] + s
                n = n // len(chars) - 1
                if n < 0:
                    break
            i += 1
            if s not in RESERVED:
                yield s

    def build_rename_map(self, decls):
        self.log(f"Generating rename map for {len(decls)} identifiers...")
        mapping = OrderedDict()
        for name in decls:
            short = next(self.name_generator)
            if short != name:
                mapping[name] = short
                self.stats['renamed'] += 1
        return mapping

    def apply_renames(self, code, mapping):
        self.log(f"Applying {len(mapping)} renames...")
        for orig, new in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
            code = re.sub(r'\b' + re.escape(orig) + r'\b', new, code)
        return code

    def obfuscate_strings(self, placeholders):
        self.log("Obfuscating strings...")
        map_out = {}
        for key, token in placeholders.items():
            if token.startswith(("'", '"', '`')):
                content = token[1:-1]
                if self.level >= 3:
                    if self.level >= 5:
                        encoded = base64.b64encode(zlib.compress(content.encode('utf-8'))).decode('ascii')
                        xor_key = random.randint(1, 255)
                        encoded = ''.join([chr(ord(c) ^ xor_key) for c in encoded])
                        repl = f'(function(_){{return {self.gen_random_var()}}})(atob("{encoded}").split("").map(c=>String.fromCharCode(c.charCodeAt(0)^{xor_key})).join(""))'
                    elif self.level >= 4:
                        encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')
                        xor_key = random.randint(1, 255)
                        encoded = ''.join([chr(ord(c) ^ xor_key) for c in encoded])
                        repl = f'(function(_){{return {self.gen_random_var()}}})(atob("{encoded}").split("").map(c=>String.fromCharCode(c.charCodeAt(0)^{xor_key})).join(""))'
                    else:
                        encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')
                        repl = f'atob("{encoded}")'
                    map_out[key] = f'(function(){{return {repl}}})()'
                    self.stats['strings'] += 1
                else:
                    map_out[key] = None
            else:
                map_out[key] = None
        return map_out

    def gen_random_var(self):
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_', k=random.randint(3, 8)))

    def add_junk_code(self, code):
        if self.level < 2:
            return code
        self.log("Adding junk code...")
        junk_snippets = [
            f'/*{self.gen_random_var()}*//*{self.gen_random_var()}*/',
            f'if(false){{{self.gen_random_var()}}}',
            f'try{{{self.gen_random_var()}}}catch(e){{}}',
            f'for(;;);{self.gen_random_var()}=0',
            f'!function(){self.gen_random_var()}()',
            f'var {self.gen_random_var()}={random.randint(0,99999)}',
            f'({self.gen_random_var()}=>{self.gen_random_var()})()',
            f'//{self.gen_random_var()}',
            f'/*{self.gen_random_var()}*//*{self.gen_random_var()}*/'
        ]
        lines = code.split('\n')
        for i in range(min(5, len(lines)//3)):
            pos = random.randint(1, len(lines)-1)
            lines.insert(pos, random.choice(junk_snippets))
        self.stats['junk'] = min(5, len(lines)//3)
        return '\n'.join(lines)

    def control_flow_flattening(self, code):
        if self.level < 5:
            return code
        self.log("Applying control flow flattening...")
        pattern = re.compile(r'\bif\s*\(([^)]+)\)\s*\{([^}]*)\}', re.DOTALL)
        def replacer(m):
            condition, body = m.group(1), m.group(2)
            key = self.gen_random_var()
            self.stats['flattened'] += 1
            return f"""
            (function(){{
                var {key} = {condition};
                switch({key} ? 1 : 0) {{
                    case 1: {body} break;
                    default:;
                }}
            }})()"""
        return pattern.sub(replacer, code)

    def hex_encode_numbers(self, code):
        if self.level < 4:
            return code
        self.log("Hex encoding numbers...")
        def replacer(m):
            num = m.group(0)
            try:
                self.stats['hex_numbers'] += 1
                return f"0x{int(float(num)):x}" if '.' not in num else num
            except:
                return num
        return re.sub(r'\b\d+\b', replacer, code)

    def string_splitting(self, code):
        if self.level < 5:
            return code
        self.log("Splitting strings...")
        def replacer(m):
            s = m.group(0)
            if len(s) < 10:
                return s
            parts = [s[i:i+3] for i in range(0, len(s), 3)]
            return '+' + '+'.join(f'"{p}"' for p in parts)
        return re.sub(r'"[^"]+"', replacer, code)

    def restore_protected(self, code, placeholders, obf_map):
        for key, orig in placeholders.items():
            repl = obf_map[key] if key in obf_map and obf_map[key] is not None else orig
            code = code.replace(key, repl)
        return code

    def process(self, code):
        self.original_code = code
        self.stats = {k: 0 for k in self.stats}
        self.log(f"Starting obfuscation (Level {self.level})")
        protected, placeholders = self.extract_protected(code)
        minified = self.minify(protected)
        if self.level >= 1:
            decls = self.find_decls(minified)
            if decls:
                minified = self.apply_renames(minified, self.build_rename_map(decls))
        if self.level >= 2:
            minified = self.add_junk_code(minified)
            minified = self.hex_encode_numbers(minified)
        if self.level >= 3:
            obf_strings = self.obfuscate_strings(placeholders)
            minified = self.restore_protected(minified, placeholders, obf_strings)
        if self.level >= 4:
            minified = self.string_splitting(minified)
        if self.level >= 5:
            minified = self.control_flow_flattening(minified)
            minified = re.sub(r'\s+', ' ', minified)
        self.stats['compressed'] = len(code) - len(minified)
        self.log(f"Obfuscation complete. Original: {len(code)} bytes, Obfuscated: {len(minified)} bytes")
        return minified

def loading_bar(duration=2, prefix='Processing'):
    for i in range(duration * 4):
        sys.stdout.write('\r' + prefix + ' [' + ('█' * (i % 4)) + (' ' * (3 - i % 4)) + ']')
        sys.stdout.flush()
        time.sleep(0.25)
    sys.stdout.write('\r' + ' ' * 50 + '\r')

def save_output(filename, content, level):
    os.makedirs("JavaDist", exist_ok=True)
    base = os.path.splitext(os.path.basename(filename))[0]
    output_path = f"JavaDist/{base}-lvl{level}.js"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(Fore.GREEN + f"\n[+] Level {level} obfuscation complete. Saved to: {output_path}" + Style.RESET_ALL)
    return output_path

def main():
    parser = argparse.ArgumentParser(
        description="Advanced JavaScript Obfuscator by Seryan",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""{Fore.CYAN}Examples:
  python main.py script.js
  python main.py script.js --level 5
  python main.py script.js --config lvl=4
  python main.py --config lvl=3 --default{Style.RESET_ALL}"""
    )
    parser.add_argument("input", nargs='?', help="Input JavaScript file")
    parser.add_argument("--level", "-l", type=int, choices=range(1, 6), help="Obfuscation level (1-5)")
    parser.add_argument("--config", "-c", help="Configuration command (e.g., 'lvl=3')")
    parser.add_argument("--default", action="store_true", help="Set configuration as default")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug mode")
    parser.add_argument("--list", action="store_true", help="List current configuration")
    parser.add_argument("--version", action="store_true", help="Show version information")
    args = parser.parse_args()

    if args.version:
        print(BANNER)
        print(f"Version: 2.0\nAuthor: Seryan\nLicense: MIT")
        return

    obfuscator = Obfuscator()

    if args.list:
        print(f"{Fore.CYAN}Current Configuration:{Style.RESET_ALL}")
        print(f"Default Level: {obfuscator.config.get('default_level', 3)}")
        return

    if args.config:
        if "lvl=" in args.config:
            try:
                level = int(args.config.split("=")[1])
                if 1 <= level <= 5:
                    obfuscator.config['default_level'] = level
                    obfuscator.save_config()
                    print(Fore.GREEN + f"Configuration saved: default_level={level}" + Style.RESET_ALL)
                    if args.default:
                        print(Fore.GREEN + "This will be used as default for future runs" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "Level must be between 1 and 5" + Style.RESET_ALL)
            except:
                print(Fore.RED + "Invalid configuration format. Use 'lvl=X' where X is 1-5" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Invalid configuration format. Use 'lvl=X'" + Style.RESET_ALL)
        return

    if not args.input:
        parser.print_help()
        return

    print(BANNER)
    level = args.level if args.level else obfuscator.config.get('default_level', 3)
    obfuscator.level = level
    obfuscator.set_debug(args.debug)

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        print(Fore.RED + f"Error: File '{args.input}' not found" + Style.RESET_ALL)
        sys.exit(1)

    if not args.debug:
        loading_bar()

    try:
        obfuscated = obfuscator.process(code)
        if args.debug:
            print(f"\n{Fore.CYAN}=== OBFUSCATION STATS (Level {level}) ==={Style.RESET_ALL}")
            print(f"Identifiers renamed: {obfuscator.stats['renamed']}")
            print(f"Strings obfuscated: {obfuscator.stats['strings']}")
            print(f"Junk code added: {obfuscator.stats['junk']}")
            print(f"Control flows flattened: {obfuscator.stats['flattened']}")
            print(f"Numbers hex-encoded: {obfuscator.stats['hex_numbers']}")
            print(f"Bytes saved: {obfuscator.stats['compressed']}")
            print(f"Execution time: {time.time() - obfuscator.start_time:.3f}s")
            print(f"\n{Fore.CYAN}=== OBFUSCATED CODE (First 500 chars) ==={Style.RESET_ALL}\n{obfuscated[:500]}...")
        save_output(args.input, obfuscated, level)
    except Exception as e:
        print(Fore.RED + f"\nError during obfuscation: {str(e)}" + Style.RESET_ALL)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
