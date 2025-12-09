# Windows Structure Introspection Tool

This project automates the extraction of opaque Microsoft internal
structures and global variable offsets from user-mode and kernel-mode
modules across different Windows builds. It uses WinDbg (`cdb.exe` and
`kd.exe`) to issue `dt`, `x`, and `lm` commands, then exports the parsed
results into an Excel workbook for documentation and reverse-engineering
purposes.

The output is a `<WindowsBuild>.xlsx` file containing one sheet per
structure and dedicated sheets for user-mode and kernel-mode variables.

## Requirements

-   Windows 10 or later
-   Windows Debugging Tools (`cdb.exe`, `kd.exe`) installed via Windows
    SDK
-   Python 3.8+
-   `openpyxl` Python package
-   Administrative privileges
-   Local kernel debugging enabled:

```
    bcdedit /set debug on
```

A reboot is required after enabling debug mode.

## Input Files

The tool reads four configuration files:

### `usermode_struct.txt`

Format:

    <full_path_to_dll> <StructureName>

### `kernel_mode_struct.txt`

Format:

    Module!StructureName

### `usermode_variable.txt`

Format:

    <full_path_to_dll> <SymbolName>

### `kernel_mode_variable.txt`

Format:

    Module!SymbolName


## Installation
```
    pip install -r requirements.txt
```

Ensure debugger paths in the script are correct.

## Usage

```
    python main.py
```

Enable debug logging:
```
    python main.py -debug
```

## Output

-   `urm-<StructName>` worksheets
-   `krnl-<StructName>` worksheets
-   `usermode_variables`
-   `kernelmode_variables`
