# NOTE THIS IS NOT A ROOTKIT!

**This is not a rootkit, this is just a user mode (Ring 3) Program that uses indirect syscalls to load a DLL into 5 random processes (you may implement a direct process, you can also request a version from me, it's just a few lines)**

The DLL is stored WITHIN the binary, as a resource (.rc), and packed into it at compile time.

You may create your own DLL for any means, maybe as a cheat?

This is just a very stealthy way to load it into a process.

Steps to build:

Open the .sln file (Solution) using Visual Studio 2022

Attach the DLL into the resources list (dont use my DLL, its just a messagebox, redefine the UserModeRookitDLL.dll)

Build that cheat!

