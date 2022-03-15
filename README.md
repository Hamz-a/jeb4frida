# JEB4Frida
Generate Frida hooks directly from JEB!

## How to use
1. Copy the python script in JEB's `scripts` folder.
2. Open the target APK in JEB GUI. Command line usage is not supported.
3. After analysis of the APK, look for a target to generate hooks for.
4. Put the cursor on the class or method you want to create a hook for. This can be done in the disassembly view or decompiler view.
5. Run the script: File > Scripts > Registered > Jeb4Frida.py .
6. Subsequent calls to the script might be done using the CMD+F2 command.
7. If the cursor is set on a method, a hook is created for that method alone while if the cursor is set on a class, hooks are generated for each method.


## TODO
1. `<clinit>` calls are currently not hooked. If you know how to do this, send PR.
2. Implement logic for native function hook generation


## Naming
Some time ago, [jeb2frida](https://github.com/Hamz-a/jeb2frida) was released. Since that name was already taken and jeb3frida does not make much sense either, jeb4frida was chosen!