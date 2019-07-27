# windows-imports-searcher

## What is this?

```cmd
C:\repnz\code\windows-imports-searcher>python windows_imports_searcher.py -h
usage: Windows Imports Searcher [-h] {search,index,merge} ...

A tool to index and search for imports and exports in executables. This tool
can create index files for indexed directories that contains executables. The
tool lets you search for imports/exports inside these directories. Index files
are basically JSON files, so you can open them and search yourself.

positional arguments:
  {search,index,merge}
    search              Search for functions in an index file
    index               Index imports of executables in certain directories
    merge               Merge indexes of different index files

optional arguments:
  -h, --help            show this help message and exit
```

## Supported Commands

This tool has several sub-commands that it supports.

### Index

This is the first step before you can search. This operation indexes all the executables in the given directories.

```cmd
usage: Windows Imports Searcher index [-h] -i INPUT_DIRS [INPUT_DIRS ...] -o
                                      OUTPUT

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_DIRS [INPUT_DIRS ...], --input-dirs INPUT_DIRS [INPUT_DIRS ...]
                        List of directories to parse.
  -o OUTPUT, --output OUTPUT
                        Output index file to create
```

Examples:

```cmd
C:\repnz\code\windows-imports-searcher>python windows_imports_searcher.py index -i c:\windows -o c_windows_index.json
Indexing c:\windows\bfsvc.exe
Indexing c:\windows\explorer.exe
Indexing c:\windows\HelpPane.exe
Indexing c:\windows\hh.exe
Indexing c:\windows\NGService.exe
Indexing c:\windows\notepad.exe
Indexing c:\windows\regedit.exe
Indexing c:\windows\splwow64.exe
Indexing c:\windows\twain_32.dll
Indexing c:\windows\winhlp32.exe
Indexing c:\windows\write.exe
```

If we open the output file we'll see it's a simple json file that contains all the imports and exports of all of those 
modules:

```json
{
  "c:\\windows": {
    "NGService.exe": {
      "imports": {
        "kernel32.dll": [
          "lstrcpy"
        ], 
        "comctl32.dll": [
          "InitCommonControls"
        ]
      }, 
      "exports": []
    }, 
    ....
 ```
 
We can index several directories together. The existing index.json was created by the following command:

<code>python windows_imports_searcher.py -i c:\windows c:\windows\system32 c:\windows\syswow64 -o index.json</code>
