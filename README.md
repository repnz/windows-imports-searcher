# windows-imports-searcher

## What is this?

I needed to find built-in ETW providers so I needed some way to search for functions that 
reference Etw functions, that's why I created this script:)

This is a tool to index and search for imports and exports in executables. This tool
can create index files for indexed directories that contains executables. The
tool lets you search for imports/exports inside these directories. Index files
are basically JSON files, so you can open them and search for yourself.

```cmd
>python windows_imports_searcher.py -h
usage: Windows Imports Searcher [-h] {search,index,merge} ...

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
>python windows_imports_searcher.py index -i c:\windows -o c_windows_index.json
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

<code>python windows_imports_searcher.py search -i c:\windows c:\windows\system32 c:\windows\syswow64 -o index.json</code>


## Search

The search command allows you to explore the index file and search for executables by imports and exports.
The search command is pretty fast.

```cmd
usage: Windows Imports Searcher search [-h] -i INPUT_INDEXES
                                       [INPUT_INDEXES ...] -f FUNCTIONS
                                       [FUNCTIONS ...] [-u]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_INDEXES [INPUT_INDEXES ...], --input-indexes INPUT_INDEXES [INPUT_INDEXES ...]
                        Index files to search in.
  -f FUNCTIONS [FUNCTIONS ...], --functions FUNCTIONS [FUNCTIONS ...]
                        Function expressions to search. Function expressions
                        are similar to WinDbg '<dll_name>!<function_name>'. You
                        can use wildcard on both sides.
                        If you don't specify module name it defaults to '*'
  -u, --unique          Flag that specifies if you want an executable to be
                        printed only once if it fits one of the conditions.
```

Say I want to search for all the executables that references etw functions, I can simply run this command:

```cmd
> python windows_imports_searcher.py search -i index.json -f Etw* Event* --unique
Reading file index.json
C:\Windows\SysWOW64\ActionCenterCPL.dll Imports ntdll.dll!EtwLogTraceEvent
C:\Windows\SysWOW64\devobj.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\SettingSyncHost.exe Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\FlightSettings.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\Faultrep.dll Imports ntdll.dll!EtwCheckCoverage
C:\Windows\SysWOW64\shacct.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\twinui.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\dabapi.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\oleacc.dll Imports ntdll.dll!EtwGetTraceLoggerHandle
C:\Windows\SysWOW64\profapi.dll Imports ntdll.dll!EtwRegisterTraceGuidsW
C:\Windows\SysWOW64\d3d9.dll Imports ntdll.dll!EtwLogTraceEvent
C:\Windows\SysWOW64\netiohlp.dll Imports ntdll.dll!EtwTraceMessageVa
C:\Windows\SysWOW64\jsproxy.dll Imports ntdll.dll!EtwUnregisterTraceGuids
C:\Windows\SysWOW64\drtprov.dll Imports ntdll.dll!EtwTraceMessage
C:\Windows\SysWOW64\autoplay.dll Imports ntdll.dll!EtwLogTraceEvent
...
...
```

You can search in multiple index files by listing them:
```cmd
> python windows_imports_searcher.py search -i win7_index.json win10_index.json -f CreateMutex* --unique
```

You can also search for multiple function expressions: (2 seconds)

```cmd
> python windows_imports_searcher.py search -i index.json -f ntdll.dll!RtlGetVersion ntdll.dll!NtCreateThread*
```

Although it's called the "imports_searcher", it can search for exports too! Say I want to search for all of the Com DLLs: (5 seconds)

```cmd
> python windows_imports_searcher.py search -i index.json -f DllGetClassObject --unique
Reading file index.json
C:\Windows\SysWOW64\ActionCenterCPL.dll Exports DllGetClassObject
C:\Windows\SysWOW64\wmdmlog.dll Exports DllGetClassObject
C:\Windows\SysWOW64\AppVClientPS.dll Exports DllGetClassObject
C:\Windows\SysWOW64\VoiceActivationManager.dll Exports DllGetClassObject
C:\Windows\SysWOW64\Windows.Management.Workplace.WorkplaceSettings.dll Exports DllGetClassObject
C:\Windows\SysWOW64\provplatformdesktop.dll Exports DllGetClassObject
```

The --unique flag specifices that an executable files should only be printed once, even if it meets several conditions.

### Merge

You can use the merge command to merge index files.

Say I've created 2 index files

```
python windows_imports_searcher.py index -i c:\first -o first.json
python windows_imports_searcher.py index -i c:\second -o second.json
```

I can merge them easily using this command:

```
python windows_imports_searcher.py merge -i first.json second.json -o merged.json
```

Note that I can index multiple files using the index command:

```
python windows_imports_searcher.py index -o c:\first c:\second -o merged.json
```
