# -*- coding: utf-8 -*-
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaMethod

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
        # Require script to be run on a decompiled Java source
        if not isinstance(unit, IJavaSourceUnit):
            print(u"❌ The focus is not on a Java Source Unit.")
            return
    
        # First let's get a class
        clazz = unit.getASTElement()
        class_name = clazz.getName()[1:-1].replace("/", ".")
        class_name_var = class_name.replace('.', '_')
        frida_hook = "   var {} = Java.use('{}');\n".format(class_name_var, class_name)

        decompiler = unit.getDecompiler()
        dex = decompiler.getCodeUnit()
        # Now let's get the methods!
        for method in clazz.getMethods():
            m = self.parse_method(method, dex, class_name_var)

            if m['method_name'] == '<init>':
                print('skipping init...') 
                continue
            frida_hook += """
    var {method_name_var} = {class_name_var}.{method_name}.overload({method_overload});
    {method_name_var}.implementation = function({method_arguments}) {{
        console.log(`[+] Hooked {class_name}.{method_name_var}({method_arguments})`);
        return {method_name_var}.call(this, {method_arguments});
    }};""".format(
            method_name_var=m['method_name_var'],
            class_name_var=class_name_var,
            class_name=class_name,
            method_name=m['method_name'],
            method_overload=', '.join(m['method_overload_parameters']),
            method_arguments=', '.join(m['method_arguments']))
            
    
        
        print("Fresh frida hook:")
        print("------------------------------------------")
        print(frida_hook)


        return 

    def parse_method(self, method, dex, class_name_var):
        method_name = method.getName()
        method_name_var = "{}_{}".format(class_name_var, method_name)

        method_parameters = method.getParameters()[1:]
        method_arguments = [m.getIdentifier().toString() for m in method_parameters]
        

        method_signature = method.getSignature()
        dex_method = dex.getMethod(method_signature)
        param_types = dex_method.getParameterTypes()

        method_overload_parameters = [p.getAddress().lstrip('L').rstrip(';').replace('/', '.') for p in param_types]
        
        
        return {
            'method_name': method_name,
            'method_name_var': method_name_var,
            'method_signature': method_signature,
            'method_parameters': method_parameters,
            'method_arguments': method_arguments,
            'method_overload_parameters': method_overload_parameters,
        }