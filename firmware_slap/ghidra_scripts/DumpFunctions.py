# Function dump
import pickle
import os
import argparse
import shlex

drop_list = ["ParentNamespace", "Tags", "StackFrame", "Class", 
        "SignatureSource", "AllVariables", "Symbol", "RepeatableCommentAsArray",
        "CommentAsArray", "Comment", "__ensure_finalizer__", "__str__",
        "__hash__",  "__unicode__", "hashCode", "__repr__", "ID",
        "FunctionThunkAddresses"]

param_attrs = ['name', 'size', 'slot', 'storage', 'length', 'memoryVariable',
        'ordinal', 'register', 'registerVariable', 'registers', 'stackOffset', 
        'stackVariable', 'firstUseOffset', 'forcedIndirect', 'formalDataType', 
        'dataType', 'variableStorage']

hiparam_attr = ['name', 'size', 'slot', 'storage', 'dataType']

var_attrs = ['name', 'dataType', 'firstUseOffset', 'registerVariable', 'length',
        'source', 'stackOffset', 'stackVariable', 'uniqueVariable',  'valid',
        'variableStorage', 'register', 'registers']

ret_attr = ['dataType', 'register', 'length', 'name']

def get_param_info(param):
    ret_dict = {}

    for attr in param_attrs:
        try:
            value = getattr(param, attr)
            ret_dict[attr] = str(value)
        except AttributeError as e:
            pass
        except java.lang.UnsupportedOperationException as e:
            pass

    try:
        ret_dict['data_type'] = str(param.getDataType())
    except AttributeError as e:
        pass

    return ret_dict

def get_var_info(var):
    ret_dict = {}

    for attr in var_attrs:
        value = getattr(var, attr)
        ret_dict[attr] = str(value)

    return ret_dict

def get_ret_info(var):
    ret_dict = {}

    for attr in ret_attr:
        value = getattr(var, attr)
        ret_dict[attr] = str(value)

    return ret_dict


def make_pickleable(func_dict):

    # Remove high level items not needed
    for item in drop_list:
        func_dict.pop(item)

    params = []
    for parm in func_dict['Parameters']:
        param_dict = get_param_info(parm)
        params.append(param_dict)
    func_dict['Parameters'] = params

    vars_list = []
    for var in func_dict['LocalVariables']:
        var_dict = get_var_info(var)
        vars_list.append(var_dict)
    func_dict['LocalVariables'] = vars_list

    # EntryPoint
    EntryPoint = {
            'offset' : str(func_dict['EntryPoint'].offset),
            'physicalAddress' : str(func_dict['EntryPoint'].physicalAddress)
            }
    func_dict['EntryPoint'] = EntryPoint

    # Ret
    func_dict['Return'] = get_ret_info(func_dict['Return'])
    func_dict['ReturnType'] = str(func_dict['ReturnType'])

    # Program name
    func_dict['Program'] = str(func_dict['Program'].name)

    # Calling Function
    func_dict['CallingFunctions'] = func_dict['CallingFunctions'].toArray()
    calling_funcs = []
    for func in func_dict['CallingFunctions']:
        t_func = {}
        t_func['Name'] = str(func.name)
        t_func['Addr'] = str(func.entryPoint)
        calling_funcs.append(t_func)

    func_dict['CallingFunctions'] = calling_funcs

    # Body
    body = []
    for addrRange in func_dict['Body'].addressRanges:
        body.append((str(addrRange.minAddress), str(addrRange.maxAddress)))

    func_dict['Body'] = body 

    func_dict['CallingConvention'] = str(func_dict['CallingConvention'])
    func_dict['Signature'] = str(func_dict['Signature'])

    return func_dict

def main(args):
    flatapi = ghidra.program.flatapi.FlatProgramAPI(getCurrentProgram(), getMonitor())
    decapi = ghidra.app.decompiler.flatapi.FlatDecompilerAPI(flatapi)
    decapi.initialize()
    decInt = decapi.getDecompiler()

    func_list = []
    function = getFirstFunction()
    while function is not None:
        if args.func_name:
            if args.func_name not in str(function.getName):
                function = getFunctionAfter(function)
                continue
        if args.func_addr:
            if args.func_addr.replace('0x','').lower() not \
                    in str(function.getEntryPoint.offset).lower():
                function = getFunctionAfter(function)
                continue


        func_dict = {}
        for x in dir(function):
            try:
                method = getattr(function,x)
                func_dict[x.replace('get','')] = method()
            except:
                pass
        func_dict['CallingFunctions'] = function.getCallingFunctions(getMonitor())
        func_dict['ProtoTypeString'] = function.getPrototypeString(True,True)

        # Several steps to get HiFunction
        DecRes = decInt.decompileFunction(function, 120, getMonitor())
        DecFunc = DecRes.getDecompiledFunction()

        Top_Prototype = str(DecFunc.getSignature())
        if True:
            c_code = DecFunc.getC()
            func_dict['c_code'] =  c_code

        HiFunc = DecRes.getHighFunction()
        HiFuncProto = HiFunc.getFunctionPrototype()
        HiFuncParamCount = HiFuncProto.getNumParams()

        HiFuncParams = []
        HiRetType = HiFuncProto.getReturnType()
        for x in range(HiFuncParamCount):
            parm = HiFuncProto.getParam(x)
            temp_parm = {}
            for attr in hiparam_attr:
                value = getattr(parm,attr)
                temp_parm[attr] = str(value)
            HiFuncParams.append(temp_parm)

        func_dict['HiParameters'] = HiFuncParams
        func_dict['HiParameterCount'] = HiFuncParamCount
        func_dict['HiRetType'] = str(HiRetType)
        func_dict['HiFuncProto'] = Top_Prototype
        func_dict = make_pickleable(func_dict)

        func_list.append(func_dict)
        print(Top_Prototype)

        function = getFunctionAfter(function)

    with open(args.Output, 'wb') as f:
        pickle.dump(func_list,f,-1)

    print("[+] Finished dumping files to {}".format(args.Output))

if __name__  == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("Output", help="Location of output pickle file")
    parser.add_argument("--func_addr", required=False,
            help="Only get one function by address")
    parser.add_argument("--func_name", required=False,
            help="Only get one function by name")

    # argparseing a nested cmd line argument
    try:
        input_args = getScriptArgs()
    except NameError as e:
        print("[!] This is a ghidra python script and cannot be run normally")
        exit(0)

    if  len(input_args) > 0:
        input_args = input_args[0]
        if len(input_args.split()) > 1:
            input_args = shlex.split(input_args)
        else:
            input_args = [input_args]
    else:
        input_args = ""

    args = parser.parse_args(input_args)
    main(args)
