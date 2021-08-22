# SharpDLLProxy

Tool to copy a specified DLL and create a proxy DLL that would allow to weaponize DLL hijacking attacks it without breaking programs that use the DLL.
A binary file, a command, or a shellcode can be used to be executed when the created DLL is used.
A `loggerCommand` is available in order to confirm the DLL hijacking vulnerability.
An `obfuscate` command exist, but it is very trivial.

```
.\sharpDLLProxy.exe
sharpDLLProxy 1.0.0
Copyright (C) 2021 sharpDLLProxy

ERROR(S):
  Required option 'dll' is missing.

  --dll              Required. Input dll file to be processed.

  --binary           Binary file to parse.

  --command          Command to execute on the target system.

  --loggerCommand    Create a log DLL in order to log each function and each time the DLL loaded.

  --show             (Default: false) Define the display option of the WinExec function.

  --obfuscate        (Default: false) Obfuscate the DLL code produced.

  --help             Display this help screen.

  --version          Display version information.
```
