from celery import Celery


from firmware_slap.function_analyzer import *
from firmware_slap.celery_tasks import *
from firmware_slap import function_handler as fh
from firmware_slap import firmware_clustering as fhc
from firmware_slap import ghidra_handler as gh
from firmware_slap import es_helper as eh
import hashlib
import os
import pickle
import tempfile
import shutil
import subprocess

#angr logging is way too verbose
import logging
import tqdm
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

use_ghidra = True 
use_elastic = False
es = None
binwalk_cmd = "binwalk -Mre {}"

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("FILE", help="File or folder to analyze")

    args = parser.parse_args()

    dirpath = tempfile.mkdtemp()

    print(dirpath)

    file_vulnerabilities = process_file_or_folder(args.FILE, dirpath)

    shutil.rmtree(dirpath)

def extract_file(file_name, work_dir):

    print("[+] Extracting {}".format(file_name))

    shutil.copy(file_name, work_dir)

    file_path = os.path.join(work_dir, file_name)

    extract_cmd = binwalk_cmd.format(file_name)

    # Extract firmware to temp dir
    cmd = extract_cmd
    print(cmd)
    print("Extracting Firmware into {}".format(work_dir))
    from subprocess import DEVNULL
    subprocess.check_call(cmd,
                        cwd=work_dir,
                        shell=True,
                        stdout=DEVNULL)

    root_fs_folder = None
    for root, subdirs, files in os.walk(work_dir):
        for filename in subdirs:

            full_path = os.path.join(root, filename)
            if os.path.isdir(full_path):

                dir_contents = os.listdir(full_path)
                root_fs_contents = ['bin', 'sbin', 'usr']

                # Check to see if common rootfs folder are there
                if all([x in dir_contents for x in root_fs_contents]):
                    print("[+] root file system discovered at {}".format(full_path))
                    root_fs_folder = full_path
                    break

    print(root_fs_folder)
    return root_fs_folder


def get_libraries(firmware_folder, work_dir):

    library_folder = os.path.join(work_dir, "libs")

    os.mkdir(library_folder)

    executables, libraries = fhc.get_executable_files(firmware_folder)

    for lib in libraries:
        shutil.copy(lib, library_folder)

    print("[+] Created library folder at {}".format(library_folder))

    return library_folder


def process_file_or_folder(file_path, work_dir):

    root_fs = extract_file(file_path, work_dir)

    if root_fs is None:
        raise RuntimeError("Could not locate root filesystem for {}".format(file_path))

    ld_path = get_libraries(root_fs, work_dir)

    return get_vulnerabilities_directory(root_fs, ld_path)

def get_vulnerabilities_directory(folder_name, ld_path):

    executables, shared_libs = fhc.get_executable_files(folder_name)

    cgi_files = [x for x in executables if '.cgi' in x]

    function_lists = get_all_funcs_async(cgi_files)

    all_arg_funcs = []

    for func_list in function_lists:
        all_arg_funcs.extend(func_list)

    all_arg_funcs = fix_functions(all_arg_funcs)

    return get_bugs_from_functions(all_arg_funcs, ld_path)

def fix_functions(all_arg_funcs):
    exclude_list = []
    for func in all_arg_funcs:

        func_name = None
        if "name" in func.keys():
            func_name = func['name']

        func['file_path'] = func['file_name']
        func['file_name'] = os.path.basename(func['file_name'])

        combined_string = func['file_name'] + func['name'] + str(func['offset'])

        func_hash = hashlib.md5(combined_string.encode('utf-8')).hexdigest()

        func['func_hash'] = func_hash

        if use_elastic:
            res = eh.search_index_hash(es, eh.function_index,  func_hash)
            if res and res['hits']['hits']:
                exclude_list.append(func)

    for func in exclude_list:
        all_arg_funcs.remove(func)

    return all_arg_funcs

def get_all_funcs_async(file_list):

    async_group = []
    done_list = []
    for file in file_list:
        async_group.append(async_get_funcs.apply_async(args=[file],
            time_limit=3600,))

    bar = tqdm.tqdm(total=len(async_group), desc="[~] Recovering function prototypes")
    while not all([x.ready() for x in async_group]):
        done_count = len([x.ready() for x in async_group if x.ready()])
        bar.update(done_count - bar.n)
        # done_list = check_files(async_group, done_list)
        time.sleep(1)
    bar.close()

    return [x.get(propagate=False) for x in async_group if not x.failed()]


def get_all_arg_funcs_async(file_list):

    async_group = []
    for file in file_list:
        async_group.append(async_get_arg_funcs.apply_async(args=[file],
            time_limit=3600,))

    bar = tqdm.tqdm(total=len(async_group), desc="[~] Recovering function prototypes")
    while not all([x.ready() for x in async_group]):
        done_count = len([x.ready() for x in async_group if x.ready()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    return [x.get(propagate=False) for x in async_group if not x.failed()]

def check_files(task_list, done_list):


    for task in task_list:
        if task.ready():
            item = task.get(propagate=False)
            file_name = item[0]['file_name'].split('/')[-1]
            if file_name not in done_list:
                done_list.append(file_name)
                print(colored('Finished {}'.format(file_name), 'white', attrs=['bold']))
    return done_list


def get_bugs_from_functions(arg_funcs, ld_path):

    for func in arg_funcs:
        if use_ghidra:
            args = gh.get_func_args(func)
        else:
            args = fh.get_func_args(func)

        ld_path="/home/chris/Tools/firmware_slap/Almond_Root/lib"
        async_task = async_trace_func.apply_async(args=[func['offset'],
                                                          args,
                                                          func['file_path'],
                                                          ld_path,
                                                          func['name']],
                                                    time_limit=120,
                                                    worker_max_memory_per_child=2048000)
        func['task']  = async_task
        func['posted_results'] = False

    bar = tqdm.tqdm(total=len(arg_funcs), desc="[~] Finding all the vulnerabilities")
    while not all([x['task'].ready() for x in arg_funcs]):
        done_count = len([x['task'].ready() for x in arg_funcs if x['task'].ready()])
        check_bugs(arg_funcs)
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()
    arg_funcs = check_bugs(arg_funcs)

    #bugs_dict = [x.get(propagate=False) for x in async_group if not x.failed()]
    return arg_funcs
    #return [x for x in bugs_dict if x]

# The computer scientist in me hates this function
def check_bugs(arg_funcs):

    for func in arg_funcs:
        if not func['posted_results'] and func['task'].ready():
            failed = func['task'].failed()
            func['result'] = func['task'].get(propagate=False)

            # Can't serialize a task
            task = func.pop('task')
            if use_elastic:
                small_func = get_small_function(func)
                eh.import_item(es, eh.function_index, small_func)

            if failed:
                func['result'] = None
            elif func['result']:
                    print_function(func)
                    make_exploit(func)
            func['task'] = task
            func['posted_results'] = True
    return arg_funcs

def get_small_function(func):

    ret_dict = {
            'name' : func['name'],
            'offset' : func['offset'],
            'file_path' : func['file_path'],
            'file_name' : func['file_name'],
            'func_hash' : func['func_hash']
            }
    if "HiFuncProto" in func.keys():
        ret_dict['prototype'] = func['HiFuncProto']

    return ret_dict

def make_exploit(func):
    print(colored("Generating exploit", 'red', attrs=['bold']))

    print(colored("This is an Almond 3 device. Using Almond 3 web request template",
        'white', attrs=['bold']))
    template_location = "../templates/Almond_Template.py"

    print(colored("Web path CGI bin path to binary /cgi-bin/{}".format(
        func['file_name']), 'white', attrs=['bold']))

    print(colored("Converting function to page name", 'white', attrs=['bold']))

    page_name = func['name'].replace('set','').replace('_','')
    if "cmd" in page_name:
        page_name = page_name.replace('cmd',"CMD")

    print(colored("func : {} -> page : {}".format(
        func['name'], page_name), 'yellow', attrs=['bold']))
    

    exploit_script = ""
    with open(template_location, 'r') as f:
        for line in f:
            if "CGI_NAME" in line:
                exploit_script += line.replace("CGI_NAME", func['file_name'])
            elif "PAGE_NAME" in line:
                exploit_script += line.replace("PAGE_NAME", page_name)
            else:
                exploit_script += line

    file_name = "{}_{}.py".format(
            func['result']['type'], func['name'])

    with open(file_name, 'w') as f:
        f.write(exploit_script)

    print(colored("Sucessfully generated {}".format(file_name), 'cyan', attrs=['bold']))


def print_function(func):
    prototype = func['HiFuncProto']
    code = func['c_code']
    file_name = func['file_name']
    func_name = func['name']
    bug = func['result']
    bug_type = bug['type']
    print(colored("{} found in {} at {}".format(
        bug_type, file_name, func_name), 'red', attrs=['bold']))

    import re
    print(colored(prototype,'cyan', attrs=['bold']))
    for arg in bug['args']:
        data = arg['value']
        data = re.sub('\\\\x[0-9][0-9]','', data)
        print(colored("\t{} : {}".format(arg['base'], data),
            'white', attrs=['bold']))
    if 'Injected_Location' in bug.keys():
        print(colored("Injected Memory Location", 'cyan', attrs=['bold']))

        data = bug['Injected_Location']['Data']
        data = re.sub('\\\\x[0-9][0-9]','', data)

        print(colored("\t{}".format(data),
            'white', attrs=['bold']))
    print(colored("Tainted memory values",'cyan', attrs=['bold']))
    for mem_val in bug['mem']:
        print(colored("{}".format(
            mem_val['BBL_DESC']['DESCRIPTION']),
            'yellow', attrs=['bold']))
        if 'DATA_ADDRS' in mem_val.keys():
            print(colored("\tMemory load addr {}".format(
                mem_val['DATA_ADDRS'][0]),
                    'white', attrs=['bold']))
        data = re.sub('\\\\x[0-9][0-9]','', mem_val['DATA'])
        print(colored("\tMemory load value {}".format(
            data),
            'white', attrs=['bold']))
        print()


if __name__ == "__main__":
    main()
