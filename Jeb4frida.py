# -*- coding: utf-8 -*-
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaMethod
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit


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
            

        if isinstance(unit, INativeSourceUnit):
            # decompiled native code
            print(u"❌ INativeSourceUnit is not implemented yet...")
            return
        
        if isinstance(unit, INativeCodeUnit):
            # assembly native code
            print(u"❌ INativeCodeUnit is not implemented yet...")
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
        
        self.gen_java_hook(java_class, java_methods)
    
    def gen_java_hook(self, java_class, java_methods):
        class_name = java_class.getType().toString()
        class_name_var = class_name.split('.')[-1]
        frida_hook = "    var {} = Java.use('{}');\n".format(class_name_var, class_name)

        for idx, java_method in enumerate(java_methods):
            method_name = java_method.getName()
            method_name_var = "{}_{}_{:x}".format(class_name_var, method_name, idx)

            method_parameters = java_method.getParameters()
            if len(method_parameters) > 0 and method_parameters[0].getIdentifier().toString() == "this":  # pop "this"
                method_parameters = method_parameters[1:]
            method_arguments = [m.getIdentifier().toString() for m in method_parameters]
            method_overload_parameters = [p.getType().getSignature().replace('/', '.').replace(';', '') for p in method_parameters]
            frida_hook += """
    var {method_name_var} = {class_name_var}.{method_name}.overload({method_overload});
    {method_name_var}.implementation = function({method_arguments}) {{
        console.log(`[+] Hooked {class_name}.{method_name_var}({method_arguments})`);
        return {method_name_var}.call(this{hack}{method_arguments});
    }};""".format(
                    method_name_var=method_name_var,
                    class_name_var=class_name_var,
                    class_name=class_name,
                    method_name=method_name,
                    method_overload=', '.join(method_overload_parameters),
                    method_arguments=', '.join(method_arguments),
                    hack=', ' if len(method_arguments) > 0 else '')

        print('FRIDA HOOOOOK!!!')
        print('0' * 100)
        print(frida_hook)
            # print("-------------")
            # for p in method_parameters:
            #     print(p.getType().getSignature().replace('/', '.').replace(';', ''))
            # print("-------------")
            # print(java_method)
            # print(java_method.getName())
            # print(method_name_var)
            # print(method_parameters)
            # print(method_arguments)
            
        
