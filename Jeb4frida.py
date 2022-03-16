# -*- coding: utf-8 -*-
#?description=Helper JEB script to generate Frida hooks
#?shortcut=
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaMethod
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit
from com.pnfsoftware.jeb.core.units import UnitUtil
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.awt import Toolkit

from java.io import File
import re

"""
Helper JEB script to generate Frida hooks
"""
class Jeb4frida(IScript):
    def run(self, ctx):
        print(u"🔥 Jeb4frida...")
        # Require script to be run in JEB GUI
        if not isinstance(ctx, IGraphicalClientContext):
            print(u"❌ This script must be run within a graphical client.")
            return

        view = ctx.getFocusedView()
        unit = view.getUnit()

        if isinstance(unit, IJavaSourceUnit) or isinstance(unit, IDexUnit):
            print(u"IJavaSourceUnit / IDexUnit detected")
            # Both IJavaSourceUnit and IDexUnit have getDecompiler()
            dexdec = unit.getDecompiler()
            self.handle_java_dex(ctx, dexdec)
            return
            

        if isinstance(unit, INativeSourceUnit) or isinstance(unit, INativeCodeUnit):
            print(u"INativeSourceUnit / INativeCodeUnit detected...")
            self.handle_native(ctx, unit)
            return
            
        return 


    def handle_java_dex(self, ctx, dexdec):
        f = ctx.getFocusedFragment()
        assert f, 'Need a focused fragment'

        # a DEX-style address: TYPENAME->METHODNAME(PARAMTYPES)RETTYPE+OFFSET
        dex_addr = f.getActiveAddress()

        # strip the offset if present
        dex_addr = dex_addr.split('+')[0]

        # we won't be looping through inner classes, for now...
        class_dex_addr = dex_addr.split('->')[0]
        java_class = dexdec.getClass(class_dex_addr, True) # True to decompile if not done yet

        if ";->" in dex_addr: # single method
            java_methods = [dexdec.getMethod(dex_addr, True)] # True to decompile if not done yet
        else: # all methods                
            java_methods = java_class.getMethods()
        
        print(u"🔥 Here\'s a fresh Frida hook...")
        print('-' * 100)
        print(self.gen_how_to(ctx))
        print(self.gen_java_hook(java_class, java_methods))
    

    def gen_java_hook(self, java_class, java_methods):
        class_name = java_class.getType().toString()
        class_name_var = class_name.split('.')[-1]
        frida_hook = "    var {} = Java.use('{}');\n".format(class_name_var, class_name)

        for idx, java_method in enumerate(java_methods):
            method_name = java_method.getName().strip('<>')
            method_name_var = "{}_{}_{:x}".format(class_name_var, method_name, idx)
            method_name = '$init' if method_name == "init" else method_name
            if method_name == "clinit": 
                print(u"//❌ Encountered <clinit>, skipping...\n//\tPS: Send PR if you know how to fix this.")
                continue
            method_parameters = java_method.getParameters()
            if len(method_parameters) > 0 and method_parameters[0].getIdentifier().toString() == "this":  # pop "this"
                method_parameters = method_parameters[1:]
            method_arguments = [m.getIdentifier().toString() for m in method_parameters]
            method_overload_parameters = []

            for p in method_parameters:
                signature = p.getType().getSignature().replace('/', '.')
                if not signature.startswith('['):
                    signature = re.sub(r'L((?:[^.]+\.)*[^.]+);', r'\1', signature)
                method_overload_parameters.append('"{}"'.format(signature))

            frida_hook += """
    var {method_name_var} = {class_name_var}.{method_name}.overload({method_overload});
    {method_name_var}.implementation = function({method_arguments}) {{
        console.log(`[+] Hooked {class_name}.{method_name}({method_arguments})`);
        return {method_name_var}.call(this{hack}{method_arguments});
    }};""".format(
                class_name_var=class_name_var,
                class_name=class_name,
                method_name_var=method_name_var,
                method_name=method_name,
                method_overload=', '.join(method_overload_parameters),
                method_arguments=', '.join(method_arguments),
                hack=', ' if len(method_arguments) > 0 else '')

        return "Java.perform(function() {{\n{}\n}});".format(frida_hook)
    

    def handle_native(self, ctx, unit):
        f = ctx.getFocusedFragment()
        assert f, 'Need a focused fragment'
        active_address = f.getActiveAddress()
        assert active_address, 'Put cursor somewhere else...'
        active_address = active_address.split('+')[0]  # strip offset

        decompiler = unit.getDecompiler()
        code_unit = decompiler.getCodeUnit()  # ICodeUnit
        elf = code_unit.getCodeObjectContainer()  # ICodeObjectUnit 

        lib_name = elf.getName()

        code_method = code_unit.getMethod(active_address) # ICodeMethod -> INativeMethodItem
        method_real_name = code_method.getName(False)  # we need the real name instead of renamed one
        func_offset = hex(code_method.getMemoryAddress()).rstrip("L")
        
        func_retval_type = code_method.getReturnType().getName(True) if code_method.getReturnType() is not None else "undefined"
        func_parameter_names = code_method.getParameterNames()
        func_parameter_types = code_method.getParameterTypes()
        func_args = ""
        for idx, func_parameter_name in enumerate(func_parameter_names):
            func_args += "this.{} = args[{}]; // {}\n        ".format(func_parameter_name, idx, func_parameter_types[idx].getName())
        if method_real_name.startswith("Java_"):
            print("Java native method detected...")
            native_pointer = "Module.getExportByName('{lib_name}', '{func_name}')".format(lib_name=lib_name, func_name=method_real_name)
        elif method_real_name.startswith(u"→"):
            print("Trampoline detected...")
            native_pointer = "Module.getExportByName('{lib_name}', '{func_name}')".format(lib_name=lib_name, func_name=method_real_name.lstrip(u"→"))
        elif re.match(r'sub_[A-F0-9]+', method_real_name):
            print("Need to calculate offset...")
            native_pointer = "Module.findBaseAddress('{lib_name}').add({func_offset})".format(lib_name=lib_name, func_offset=func_offset)
        else:
            print("Everything else...")
            native_pointer = "Module.getExportByName('{lib_name}', '{func_name}')".format(lib_name=lib_name, func_name=method_real_name)


        frida_hook = u"""
Interceptor.attach({native_pointer}, {{ // offset {func_offset}
    onEnter(args) {{
        {func_args}
    }}, onLeave(retval) {{ // return type: {func_retval_type}
        console.log(`[+] Hooked {lib_name}[{func_name}]({func_params}) -> ${{retval}}`);
        // retval.replace(0x0)
    }}
}});""".format(lib_name=lib_name, func_name=method_real_name, native_pointer=native_pointer,
        func_offset=func_offset, func_retval_type=func_retval_type, func_args=func_args,
        func_params=', '.join(func_parameter_names))

        print(u"🔥 Here\'s a fresh Frida hook...")
        print('-' * 100)
        print(self.gen_how_to(ctx))
        print(frida_hook)

    def gen_how_to(self, ctx):
        project = ctx.getMainProject()
        assert project, "Need a project..."

        # Find the first IApkUnit in the project
        apk = project.findUnit(IApkUnit)
        assert apk, "Need an apk unit"

        return "// Usage: frida -U -f {} -l hook.js --no-pause".format(apk.getPackageName())
