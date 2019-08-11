#!/usr/bin/env python
import angr
from angr import sim_options as so
import claripy
import argparse
#import function_handler as fh
from firmware_slap.function_analyzer import *
from firmware_slap import function_handler as fh
from firmware_slap import command_injection
from multiprocessing import Process, Queue
#from multiprocessing.dummy import Process, Queue
from firmware_slap.Limited_Process import Limited_Process
import psutil
import IPython
import time

#angr logging is way too verbose
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

file_name = None
limited_processes = []

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("FILE")
    parser.add_argument("-L", "--LD_PATH", default="", help="Path to libraries to load")

    args = parser.parse_args()

    print("[+] Getting argument functions")
    arg_funcs = fh.get_arg_funcs(args.FILE)
    #arg_funcs = [x for x in arg_funcs if 'remove_routing_rule' in x['name']]
    print("[+] Analyzing {} functions".format(len(arg_funcs)))

    global file_name
    file_name = args.FILE

    for func in arg_funcs:
        func['file_name'] = file_name

    cores = psutil.cpu_count() -1
    func_list = list(arg_funcs)
    func_iter = 0
    func_timeout = 120
    #Available mememory divided by cores
    mem_limit = (psutil.virtual_memory()[1] / (1024*1024)) / cores
    print("Memory Limit : {} MB | Analysis Timeout : {} seconds".format(mem_limit, func_timeout))
    global limited_processes
    while func_iter < len(func_list) or len(limited_processes): #len(func_list):
        while len(limited_processes) < cores and len(func_list) > 0 and func_iter < len(func_list):
            proc_queue = Queue()
            m_data = (func_list[func_iter], proc_queue, args.LD_PATH)
            p = Process(target=trace_function, args=m_data)
            p.start()
            my_proc = Limited_Process(p, func_list[func_iter], func_timeout, mem_limit, proc_queue)
            limited_processes.append(my_proc)
            print("Starting {}".format(func_list[func_iter]['name']))
            func_iter += 1

        #Check for results
        to_remove = []
        for lim_proc in limited_processes:

            result = lim_proc.get()

            #Process returned!
            if result is not None and type(result) is not "str" and result is not "timeout":
                if "vulnerable" in result.stashes.keys():
                    print("[+] Memory Corruption {}".format(lim_proc.function['name']))
                    path = result.stashes['vulnerable'][0]
                    if path.globals['args']:
                        print_format = "{:<16} : {:<15} | {}"
                        print("[+] Function Arguments")
                        print(print_format.format("Arg Location", "Arg Type", "Arg Value"))

                    for x, y, z in path.globals['args']:
                        value = unravel(y, z, path)
                        pretty_print(x['ref'], str(y), value)
                    display_corruption_location(path)

                elif "exploitable" in result.stashes.keys() and len(result.stashes['exploitable']) > 0:
                    print("[+] Command Injection {}".format(lim_proc.function['name']))
                    path = result.stashes['exploitable'][0]

                    val_loc = path.globals['val_offset']
                    val_addr = path.globals['val_addr']
                    solved_loc = hex(path.se.eval(val_loc))
                    solved_addr = hex(path.se.eval(val_addr))

                    if path.globals['args']:
                        print_format = "{:<16} : {:<15} | {}"
                        print("[+] Function Arguments")
                        print(print_format.format("Arg Location", "Arg Type", "Arg Value"))
                    for x, y, z in path.globals['args']:
                        value = unravel(y, z, path)
                        pretty_print(x['ref'], str(y), value)
                    print("[+] Command Injected memory location:")
                    temp = unravel(None, val_addr, path)
                    pretty_print(solved_addr, "char *", temp)

                    display_corruption_location(path, path.globals['cmd'])


                    #temp = unravel(None, val_loc, path)
                    #pretty_print(solved_loc, "char *", temp)

                else:
                    print("{} returned no results".format(lim_proc.function['name']))

                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.mem_overused() or lim_proc.time_is_up():
                print("{} timed out or reached memory limit".format(lim_proc.function['name']))
                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.finished:
                print("{} finished".format(lim_proc.function['name']))
                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)

        #Remove processes
        for lim_proc in to_remove:
            limited_processes.remove(lim_proc)
        time.sleep(.1)




if __name__ == "__main__":
    main()
