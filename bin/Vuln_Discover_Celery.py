#!/usr/bin/env python

from celery import Celery

from firmware_slap.function_analyzer import *
from firmware_slap.celery_tasks import *
from firmware_slap import firmware_clustering as fhc
from firmware_slap import es_helper as eh
import hashlib
import os
import pickle

#angr logging is way too verbose
import argparse
import logging
import tqdm
import time
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

use_ghidra = False 
use_elastic = False
es = None
fh = None

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("FILE", help="File or folder to analyze")
    parser.add_argument("-L",
                        "--LD_PATH",
                        default="",
                        help="Path to libraries to load")
    parser.add_argument("-D",
                        "--DUMP_PATH",
                        default="Vulnerable_Pickle",
                        help="Pickle name to dump JSON")
    parser.add_argument("-e",
                        "--elastic",
                        default=False,
                        help="Use elastic search database",
                        action="store_true")
    parser.add_argument("--delete_index",
                        default=False,
                        help="Delete elastic index",
                        action="store_true")

    args = parser.parse_args()

    global use_elastic
    global es
    use_elastic = args.elastic
    es = eh.get_es()

    if use_elastic:
        eh.build_index(es, eh.vulnerability_index, args.delete_index)
        eh.build_index(es, eh.function_index, args.delete_index)

    global fh
    if use_ghidra:
        from firmware_slap import ghidra_handler
        fh = ghidra_handler
    else:
        from firmware_slap import function_handler
        fh = function_handler
     
    file_vulnerabilities = process_file_or_folder(args.FILE, args.LD_PATH)

    with open(args.DUMP_PATH, 'wb') as f:
        pickle.dump(file_vulnerabilities, f, -1)


def process_file_or_folder(file_path, ld_path):

    file_path = os.path.abspath(file_path)
    ld_path = os.path.abspath(ld_path)

    if os.path.isdir(file_path):
        return get_vulnerabilities_directory(file_path, ld_path)
    else:
        return get_vulnerabilities(file_path, ld_path)


def get_vulnerabilities_directory(folder_name, ld_path):

    executables, shared_libs = fhc.get_executable_files(folder_name)

    all_files = executables + shared_libs
    # all_files = executables

    function_lists = get_all_arg_funcs_async(all_files)

    all_arg_funcs = []

    for func_list in function_lists:
        all_arg_funcs.extend(func_list)

    all_arg_funcs = fix_functions(all_arg_funcs)

    return get_bugs_from_functions(all_arg_funcs, ld_path)


def fix_functions(all_arg_funcs):
    exclude_list = []
    for func in all_arg_funcs:

        func['file_path'] = func['file_name']
        func['file_name'] = os.path.basename(func['file_name'])

        combined_string = func['file_name'] + func['name'] + str(
            func['offset'])

        func_hash = hashlib.md5(combined_string.encode('utf-8')).hexdigest()

        func['func_hash'] = func_hash

        if use_elastic:
            res = eh.search_index_hash(es, eh.function_index, func_hash)
            if res and res['hits']['hits']:
                exclude_list.append(func)

    for func in exclude_list:
        all_arg_funcs.remove(func)

    return all_arg_funcs


def get_all_arg_funcs_async(file_list):

    async_group = []
    for file in file_list:
        async_group.append(
            async_get_arg_funcs.apply_async(
                args=[file],
                time_limit=3600,
            ))

    bar = tqdm.tqdm(total=len(async_group),
                    desc="[~] Getting functions with arguments")
    while not all([x.successful() or x.failed() for x in async_group]):
        done_count = len([x.successful() or x.failed() for x in async_group if x.successful() or x.failed()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    return [x.get(propagate=False) for x in async_group if not x.failed()]


def get_all_funcs_async(file_list):

    async_group = []
    for file in file_list:
        async_group.append(
            async_get_funcs.apply_async(
                args=[file],
                time_limit=3600,
            ))

    bar = tqdm.tqdm(total=len(async_group),
                    desc="[~] Getting functions with arguments")
    while not all([x.successful() or x.failed() for x in async_group]):
        done_count = len([x.successful() or x.failed() for x in async_group if x.successful() or x.failed()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    return [x.get(propagate=False) for x in async_group if not x.failed()]


def get_bugs_from_functions(arg_funcs, ld_path):

    for func in arg_funcs:
        args = fh.get_func_args(func)

        async_task = async_trace_func.apply_async(
            args=[
                func['offset'], args, func['file_path'], ld_path, func['name']
            ],
            time_limit=120,
            worker_max_memory_per_child=2048000)
        func['task'] = async_task
        func['posted_results'] = False

    bar = tqdm.tqdm(total=len(arg_funcs),
                    desc="[~] Finding all the vulnerabilities")
    while not all([x['task'].ready() for x in arg_funcs]):
        done_count = len(
            [x['task'].ready() for x in arg_funcs if x['task'].ready()])
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
                print("\nFound {} in {} in {}".format(
                    func['result']['type'], func['result']['func_name'],
                    func['result']['file_name']))
                if use_elastic:
                    eh.import_item(es, eh.vulnerability_index, func)
            func['task'] = task
            func['posted_results'] = True
    return arg_funcs


def get_vulnerabilities(file_name, ld_path):
    print("[+] Getting argument functions")
    if use_ghidra:
        arg_funcs = fh.get_function_information(file_name)
    else:
        arg_funcs = fh.get_arg_funcs(file_name)
    for func in arg_funcs:
        func['file_name'] = file_name

    arg_funcs = fix_functions(arg_funcs)
    #arg_funcs = [x for x in arg_funcs if 'mtd_write_firmware' in x['name']]
    print("[+] Analyzing {} functions".format(len(arg_funcs)))

    return get_bugs_from_functions(arg_funcs, ld_path)


def get_small_function(func):

    ret_dict = {
        'name': func['name'],
        'offset': func['offset'],
        'file_path': func['file_path'],
        'file_name': func['file_name'],
        'func_hash': func['func_hash']
    }
    if "HiFuncProto" in func.keys():
        ret_dict['prototype'] = func['HiFuncProto']

    return ret_dict


if __name__ == "__main__":
    main()
