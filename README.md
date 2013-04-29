#fulldump-relocation-checker

Usage: `fulldump-relocation-checker.exe <dumpfile> <dllfile>`

Load a Windows full memory dump and compare the memory information with the
memory that should be present when using the matching DLL. If code is
altering/monkeypatching/corrupting the TEXT memory of a process, this
tool should show it.
