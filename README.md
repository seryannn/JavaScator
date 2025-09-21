<img width="1920" height="1440" alt="image" src="https://github.com/user-attachments/assets/9a282fa2-4cc5-4652-9d89-ac5c9980600f" />

# JavaScator v2.0
**Advanced JavaScript Obfuscator by Seryan**

JavaScator is an advanced Python-based JavaScript obfuscator designed to protect your code from reverse engineering and unauthorized reading. It supports multiple obfuscation levels with advanced techniques such as minification, variable renaming, junk code injection, string encryption, and control flow flattening.

---

## Features

- **Minification**: Removes unnecessary spaces, tabs, and empty lines.
- **Variable & Function Renaming**: Replaces identifiers with short, random names.
- **String Obfuscation**: Base64 encoding, compression, and XOR to make strings unreadable.
- **Junk Code Injection**: Adds non-functional code snippets to complicate analysis.
- **Control Flow Flattening**: Converts conditional structures into hard-to-follow blocks.
- **Hexadecimal Number Encoding**: Converts numbers to hexadecimal notation.
- **Multi-level Obfuscation (1-5)**: Adjust the complexity to your needs.
- **Debug Mode**: Provides detailed logs of all transformations applied.
- **Config Management**: Allows setting a default obfuscation level.

---

## Installation

Clone the repository and ensure you have Python 3.7+ installed along with required dependencies:

```bash
git clone https://github.com/seryannn/JavaScator.git
cd JavaScator
pip install -r requirements.txt
````

---

## Usage

```bash
python main.py <file.js> [options]
```

### Main Options

| Option         | Description                                       |
| -------------- | ------------------------------------------------- |
| `--level, -l`  | Obfuscation level (1-5)                           |
| `--config, -c` | Set configuration, e.g., `lvl=3`                  |
| `--default`    | Save the configuration as default for future runs |
| `--debug, -d`  | Enable debug mode for detailed logs               |
| `--list`       | Display current configuration                     |
| `--version`    | Show version and author information               |

### Examples

```bash
python main.py.py script.js
python main.py.py script.js --level 5
python main.py.py --config lvl=4 --default
python main.py script.js --debug
```

---

## Project Structure

```
JavaScator/
├── main.py       # Main script
├── JavaDist/      # Output folder for obfuscated files
├── JavaScator-Global/           
├── requirements.txt       # Python dependencies
└── README.md
```

---

## Obfuscation Levels

| Level | Main Features                                          |
| ----- | ------------------------------------------------------ |
| 1     | Basic minification and renaming                        |
| 2     | Junk code injection, hexadecimal number encoding       |
| 3     | Advanced string obfuscation (Base64, compression, XOR) |
| 4     | String splitting for extra protection                  |
| 5     | Control flow flattening and additional optimizations   |

---

## Debug Mode Stats

In debug mode, JavaScator shows:

* Renamed identifiers
* Obfuscated strings
* Junk code added
* Flattened control flows
* Hexadecimal-encoded numbers
* Bytes saved
* Execution time

---

## License

MIT License © Seryan



