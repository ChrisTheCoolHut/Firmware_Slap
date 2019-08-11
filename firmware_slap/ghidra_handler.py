import shutil
import tempfile
import os
import pickle
import subprocess
# analyzeHeadless . Project_test -import $1 -scriptPath ./ -preScript SetDecompilerOptions.py -postScript DumpFunctions.py "./Output_File"

run_headless_command = "analyzeHeadless {} {} -max-cpu 1 -import {} -scriptPath {} -preScript {} -postScript {} \"{}\""
helper_path = os.path.dirname(__file__)
ghidra_headless = "analyzeHeadless"
ghidra_scripts_dir = os.path.join(helper_path, "ghidra_scripts")


def check_for_headless():
    
    if shutil.which(ghidra_headless):
        return True
    else:
        print("[~] Please install Ghidra and add analyzeHeadless to the PATH")
        return False

def load_functions_from_file(file_name):

    ret_list = []
    with open(file_name, 'rb')  as f:
        ret_list = pickle.load(f)
    return ret_list

def get_scripts_directory():

    abs_path = os.path.abspath(__file__)
    lib_dir = os.path.dirname(abs_path)
    scripts_dir = os.path.join(lib_dir, ghidra_scripts_dir)

    return scripts_dir

def run_dump_functions(dirpath, base_name, file_name, script_path, output_file_path):

    set_options = os.path.join(ghidra_scripts_dir, "SetDecompilerOptions.py")
    dump_funcs = os.path.join(ghidra_scripts_dir, "DumpFunctions.py")

    project_name = "project_{}".format(base_name)

    dump_cmd = run_headless_command.format(
            dirpath,
            project_name,
            file_name,
            script_path,
            set_options,
            dump_funcs,
            output_file_path
            )

    print(dump_cmd.replace(' -', '\n\t-'))

    exit_code = subprocess.call(dump_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

    #if os.path.exists(output_file_path):
    #    print("Success!")
    
def get_function_information(file_name):

    if not check_for_headless():
        return []

    functions = []
    dirpath = tempfile.mkdtemp()
    base_name = os.path.basename(file_name)
    full_output_path = os.path.join(dirpath, base_name)

    scripts_dir = get_scripts_directory()

    run_dump_functions(dirpath, base_name, file_name, scripts_dir, full_output_path)

    print(full_output_path)
    if os.path.exists(full_output_path):
        functions = load_functions_from_file(full_output_path)
    else:
        print("Failed to get function information for file {}".format(
            file_name))

    shutil.rmtree(dirpath)

    functions = [r2_compatible(x) for x in functions]

    return functions

def r2_compatible(func):

    func['name'] = func['Name']
    func['offset']  = int(func['EntryPoint']['offset'])

    return func

def fix_angr_data_type(dataType):
    if "undefined" in dataType:
        return "int"
    if "uint" in dataType:
        return dataType.replace("uint","int")

def get_func_args(func, useHiFunc=True):

    arg_list = []
    param_list = "Parameters"
    if useHiFunc:
        param_list = "HiParameters"

    for param in func[param_list]:
        param_type = param['dataType']
        param_type = fix_angr_data_type(param_type)
        param['type'] = param_type
        if 'storage' in param.keys():
            param['ref'] = param['storage']
        else:
            param['ref'] = param['variableStorage']
    return func[param_list]




# You want to use HiFunc, that's the decompiled function
def get_arg_funcs(file_name, useHiFunc=True):
    if useHiFunc:
        return [x for x in get_function_information(file_name) if len(x) > 0 and x['HiParameterCount'] > 0]
    else:
        return [x for x in get_function_information(file_name) if len(x) > 0 and x['ParameterCount'] > 0]

    
