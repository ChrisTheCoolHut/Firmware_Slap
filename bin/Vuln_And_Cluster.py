#!/usr/bin/env python

import argparse
import os
import tqdm
import IPython
import pickle
import psutil
from multiprocessing import Pool, cpu_count, Queue, Process
from firmware_slap import function_handler as fh
from firmware_slap import function_analyzer as fa
from firmware_slap import function_clustering as fc
from firmware_slap import firmware_clustering as fhc
from firmware_slap.Limited_Process import Limited_Process
'''
import .lib.function_handler as fh
import .lib.function_analyzer as fa
import .lib.function_clustering as fhc
import .lib.firmware_clustering as fc
'''

limited_processes = []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("Directory")
    parser.add_argument("-L",
                        "--LD_PATH",
                        default="",
                        help="Path to libraries to load")
    parser.add_argument("-F", "--Function", default="")
    parser.add_argument("-V", "--Vuln_Pickle", default="")

    args = parser.parse_args()

    executables, shared_libs = fhc.get_executable_files(args.Directory)

    all_files = executables + shared_libs

    all_arg_funcs = []

    m_pool = Pool()

    print("Getting functions from executables")
    for x, y in zip(m_pool.map(fh.get_arg_funcs, all_files), all_files):
        for func in x:
            func['file_name'] = y
            all_arg_funcs.append(func)

    m_pool.close()
    m_pool.join()

    if args.Vuln_Pickle is "":
        cores = psutil.cpu_count() - 1
        mem_limit = (psutil.virtual_memory()[1] / (1024 * 1024)) / cores

        vulns = get_vulnerabilities(all_arg_funcs, cores, mem_limit,
                                    args.LD_PATH)

        with open("Directory_Vulnerabilities", 'wb') as f:
            pickle.dump(vulns, f, -1)
    else:
        print("[+] Loading from pickle file {}".format(args.Vuln_Pickle))
        with open(args.Vuln_Pickle, 'rb') as f:
            vulns = pickle.load(f)

    print("[+] Getting sparse functions")

    all_functions = fhc.get_firmware_sparse(all_files)
    bad_prefix = ["fcn.", "sub.", "loc.", "aav.", "sym._fini", "sym._init"]

    all_functions = [
        x for x in all_functions
        if not any([y in x['name'] for y in bad_prefix])
    ]

    bad_features = [
        'bits', 'calltype', 'maxbound', 'minbound', 'offset', 'size'
    ]
    for func in all_functions:
        for feat in bad_features:
            func.pop(feat)

    func_labels = fhc.plot_clustering(all_functions, True)
    #func_labels = fhc.single_cluster(all_functions, len(vulns))

    file_names = [x['file_name'] for x in all_functions]
    func_names = [x['name'] for x in all_functions]

    clust_group = [x for x in zip(file_names, func_names, func_labels)]
    vuln_labels = {}

    if args.Function != "":
        for k in list(vulns.keys()):
            if args.Function not in k:
                vulns.pop(k)
    for func_ident in vulns.keys():
        file_name = func_ident.split(':')[0].rstrip(' ')
        func_name = func_ident.split(':')[1].lstrip(' ')
        try:
            label = list(
                filter(lambda x: x[0] in file_name and x[1] in func_name,
                       clust_group))[0]
            vuln_labels[label[2]] = func_ident
        except:
            pass
            #IPython.embed()

        #vuln_labels.append((func_ident, label))

    for x, y, z in zip(file_names, func_names, func_labels):
        test = not any([y in a for a in vulns.keys()])
        #test2 = not any([x in a for a in vulns.keys()])
        #print(test,test2)
        if z in vuln_labels.keys() and test:
            x = x.split('/')[-1]
            print("{:<30} | {:<30} | {} -> {}".format(x, y, z, vuln_labels[z]))


def get_vulnerabilities(file_functions, cores=1, mem_limit=2048, ld_path=""):
    func_iter = 0
    func_timeout = 120
    vulnerabilities = {}
    global limited_process

    while func_iter != len(file_functions) - 1:
        while len(limited_processes) < cores and len(
                file_functions) > 0 and func_iter < len(file_functions):
            proc_queue = Queue()
            m_data = (file_functions[func_iter], proc_queue, ld_path)
            p = Process(target=fa.trace_function, args=m_data)
            p.start()
            my_proc = Limited_Process(p, file_functions[func_iter],
                                      func_timeout, mem_limit, proc_queue)
            limited_processes.append(my_proc)
            print("Starting {}".format(file_functions[func_iter]['name']))
            func_iter += 1

        #Check for results
        to_remove = []
        for lim_proc in limited_processes:

            result = lim_proc.get()

            #Process returned!
            if result is not None and type(
                    result) is not "str" and result is not "timeout":
                print("{} {} : {}".format(lim_proc.function['file_name'],
                                          lim_proc.function['name'], result))
                vuln_key = "{} : {}".format(lim_proc.function['file_name'],
                                            lim_proc.function['name'])
                vuln_value = ""
                if "vulnerable" in result.stashes.keys():
                    print("[+] Memory Corruption {}".format(
                        lim_proc.function['name']))
                    path = result.stashes['vulnerable'][0]
                    if path.globals['args']:
                        print_format = "{:<16} : {:<15} | {}"
                        print("[+] Function Arguments")
                        print(
                            print_format.format("Arg Location", "Arg Type",
                                                "Arg Value"))

                    for x, y, z in path.globals['args']:
                        value = fa.unravel(y, z, path)
                        print("{} : {:<5} | {}".format(x['ref'], str(y),
                                                       value))
                        vuln_value += "{} : {:<5} | {}".format(
                            x['ref'], str(y), value)
                    fa.display_corruption_location(path)

                elif "exploitable" in result.stashes.keys() and len(
                        result.stashes['exploitable']) > 0:
                    path = result.stashes['exploitable'][0]
                    val_loc = path.globals['val_offset']
                    val_addr = path.globals['val_addr']
                    solved_loc = hex(path.se.eval(val_loc))
                    solved_addr = hex(path.se.eval(val_addr))

                    if path.globals['args']:
                        print_format = "{:<16} : {:<15} | {}"
                        print("[+] Function Arguments")
                        print(
                            print_format.format("Arg Location", "Arg Type",
                                                "Arg Value"))

                    for x, y, z in path.globals['args']:
                        value = fa.unravel(y, z, path)
                        print("{} : {:<5} | {}".format(x['ref'], str(y),
                                                       value))
                        vuln_value += "{} : {:<5} | {}".format(
                            x['ref'], str(y), value)
                    print("[+] Command Injected memory location:")
                    temp = fa.unravel(None, val_addr, path)
                    fa.pretty_print(solved_addr, "char *", temp)
                    fa.display_corruption_location(path)
                vulnerabilities[vuln_key] = vuln_value

                #file_functions.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.mem_overused() or lim_proc.time_is_up():
                #file_functions.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.finished:
                #file_functions.remove(lim_proc.function)
                to_remove.append(lim_proc)

        #Remove processes
        for lim_proc in to_remove:
            limited_processes.remove(lim_proc)
    return vulnerabilities


if __name__ == "__main__":
    main()
