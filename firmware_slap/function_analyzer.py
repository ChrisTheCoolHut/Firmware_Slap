import angr
from angr import sim_options as so
import claripy
import argparse
#import function_handler as fh
from . import function_handler as fh
from . import command_injection
from multiprocessing import Process, Queue
#from multiprocessing.dummy import Process, Queue
from .Limited_Process import Limited_Process
import psutil
import IPython
from termcolor import colored
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

    args = parser.parse_args()

    print("[+] Getting argument functions")
    arg_funcs = fh.get_arg_funcs(args.FILE)

    global file_name
    file_name = args.FILE

    cores = psutil.cpu_count() -1
    func_list = list(arg_funcs)
    func_iter = 0
    func_timeout = 120
    #Available mememory divided by cores
    mem_limit = (psutil.virtual_memory()[1] / (1024*1024)) / cores
    global limited_processes
    while len(func_list):
        while len(limited_processes) < cores and len(func_list) > 0 and func_iter < len(func_list):
            proc_queue = Queue()
            m_data = (func_list[func_iter], proc_queue)
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
                print("{} : {}".format(lim_proc.function['name'], result))
                if "vulnerable" in result.stashes.keys():
                    path = result.stashes['vulnerable'][0]
                    for x,y,z in path.globals['args']:
                        value = unravel(y, z, path)
                        print("{} : {:<5} | {}".format(x['ref'],
                            str(y),
                            value))
                elif "exploitable" in result.stashes.keys() and len(result.stashes['exploitable']) > 0:
                    path = result.stashes['exploitable'][0]
                    for x,y,z in path.globals['args']:
                        value = unravel(y, z, path)
                        print("{} : {:<5} | {}".format(x['ref'],
                            str(y),
                            value))


                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.mem_overused() or lim_proc.time_is_up():
                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)
                lim_proc.die()

            elif lim_proc.finished:
                func_list.remove(lim_proc.function)
                to_remove.append(lim_proc)

        #Remove processes
        for lim_proc in to_remove:
            limited_processes.remove(lim_proc)
        time.sleep(.1)


def unravel(ptr, clarip, state):
    if ptr is not None and 'pts_to' in ptr._fields:
        addr = state.se.eval(clarip)
        try:
            value_at = state.memory.load(addr) #Don't know lenth
        except AttributeError as e: #'SimPagedMemory' object has no attribute '_updated_mappings'
            return None
        if "char" in ptr.name:
            max_str_len = 150
            curr_len    = 4
            string_val  = state.se.eval(value_at, cast_to=bytes)
            while string_val[-1] is not 0 and curr_len < max_str_len:
                value_at = state.memory.load(addr, curr_len)
                string_val = state.se.eval(value_at, cast_to=bytes)
                curr_len += 1
            return("{} -> {}".format(hex(addr), string_val))

        return("{} -> {}".format(hex(addr), unravel(None, value_at, state)))
    else:
        if ptr is not None and "char" in ptr.name:
            return(state.se.eval(clarip, cast_to=bytes))

        #Test for ptr
        try:
            end_val_addr            = state.se.eval(clarip)
            end_val_deref_claripy   = state.memory.load(end_val_addr)
            end_val_solved          = state.se.eval(end_val_deref_claripy, cast_to=bytes)
            if any(x > 0 for x in end_val_solved):
                #try em out!
                max_byte_len    = 150
                curr_len        = 4
                while end_val_solved[-1] is not 0 and curr_len < max_byte_len:
                    end_val_deref_claripy   = state.memory.load(end_val_addr, curr_len)
                    end_val_solved          = state.se.eval(end_val_deref_claripy,
                            cast_to=bytes)
                    curr_len += 1
                return("{} -> {}".format(hex(end_val_addr), end_val_solved))
        except AttributeError as e: #AttributeError: 'SimPagedMemory' object has no attribute '_updated_mappings'
            pass


        end_val = hex(state.se.eval(clarip))
        return(end_val)


def trace_function(func, proc_queue, ld_path=""):
    start_addr  = func['offset']
    file_name = func['file_name']
    args        = fh.get_func_args(func)

    proc_queue.put(do_trace(start_addr, args, file_name=file_name, ld_path=ld_path)[1])

def check_actions(path):
    for action in path.history.actions:
        if isinstance(action, angr.state_plugins.sim_action.SimActionData) \
                and action.actual_value is not None:
            action_value = path.solver.eval(action.actual_value, cast_to=bytes, extra_constraints=[path.regs.pc == b"CCCC"])
            if action_value == b"CCCC":
                continue
            if len(action_value) > 4:
                return True

    return False

import claripy
big_addr = 0x1000000
class web_get_hook(angr.SimProcedure):
    def run(self):
        temp = claripy.BVS("web_val", 30 *8) # 30 byte string
        global big_addr
        big_addr += 8
        self.state.memory.store(big_addr, temp, 30)
        return big_addr



def do_trace(start_addr, args, file_name=None, ld_path=""):

    #Options to track memory events
    my_extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,
            so.TRACK_MEMORY_ACTIONS, so.ACTION_DEPS}
    base_addr = fh.get_base_addr(file_name)
    my_extra = angr.options.resilience.union(my_extras)
    p = angr.Project(file_name, main_opts={'base_addr' : base_addr}, ld_path=ld_path)

    #Hook for cmd inj
    system_list = ['system', 'execv', 'execve',
        'popen', 'execl', 'execle', 'execlp', 
        'do_system']
    for sys_type in system_list:
        try:
            p.hook_symbol(sys_type, command_injection.SystemLibc())
        except:
            pass
    try:
        p.hook_symbol("web_get", web_get_hook())
    except:
        print("oops")

    #Get function arg types
    arg_types = []
    for x in args:
        if x is not None and 'type' in x.keys():
            x = x['type']
            if x is not None:
                try:
                    arg_types.append(angr.sim_type.parse_type(x))
                except:
                    if "*" in x:
                        x = "byte *"
                    else:
                        x = "int"
                    arg_types.append(angr.sim_type.parse_type(x))
    
    #List comprehension does not like angr projects
    clarip_vars = []
    for arg in arg_types:
        temp_arg = claripy.BVS(arg.name, arg.with_arch(p.arch).size)
        clarip_vars.append(temp_arg)

    args_dict = zip(args, arg_types, clarip_vars)
    state = p.factory.call_state(start_addr, *clarip_vars, add_options=my_extra)
    state.globals['exploitable'] = False
    state.globals['args'] = args_dict
    simgr = p.factory.simgr(state, save_unconstrained=True)

    #Memory Corruption
    def check_mem_corrupt(simgr):
        simgr.stashes['exploitable'] = []
        for path in simgr.stashes['active']:
            if path.globals['exploitable']:
                simgr.stashes['exploitable'].append(path)
        if len(simgr.stashes['exploitable']) > 0:
            simgr.stashes['active'] = []
            return simgr
        if len(simgr.unconstrained):
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
                    if check_actions(path):
                        path.add_constraints(path.regs.pc == b"CCCC")
                        if path.satisfiable():
                            simgr.stashes['vulnerable'].append(path)
                        simgr.stashes['unconstrained'].remove(path)
                        #Early return?
                        simgr.drop(stash='active')
        return simgr

    try:
        import sys
        sys.stdout.encoding = 'UTF-8' #AttributeError: 'LoggingProxy' object has no attribute 'encoding'
    except AttributeError as e: #AttributeError: readonly attribute
        pass

    try:
        simgr.explore(step_func=check_mem_corrupt)
    except AttributeError as e: #AttributeError: 'bytes' object has no attribute 'spec_type'
        pass

    return p,simgr


def display_corruption_location(path, check_val="CCCC"):
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    for action in path.history.actions:
        if action.type != 'constraint':
            if action.action == 'read' or action.action == 'write':
                action_data = path.se.eval(action.data, cast_to=bytes)
                if check_val in action_data.decode('utf-8','ignore'):
                    print("BBL_ADDR  : {}".format(hex(action.bbl_addr)))
                    if action.actual_addrs is not None:
                        for addr in action.actual_addrs:
                            print("DATA ADDR : {}".format(hex(addr)))
                    print("DATA      : {}".format(repr(action_data).replace(check_val, FAIL + check_val + ENDC)))


def get_corruption_location(proj, path, check_val="CCCC"):
    corrupt_locations = []
    bbl_addrs = []
    for action in path.history.actions:
        if action.type != 'constraint':
            if action.action == 'read' or action.action == 'write':
                action_data = path.se.eval(action.data, cast_to=bytes)
                if check_val in action_data.decode('utf-8','ignore') and action.bbl_addr not in bbl_addrs:
                    action_dict = {}
                    action_dict['BBL_ADDR'] = hex(action.bbl_addr)
                    action_dict['BBL_DESC'] = get_desc_and_dis(proj, action.bbl_addr)
                    bbl_addrs.append(action.bbl_addr)
                    if action.actual_addrs is not None:
                        action_dict['DATA_ADDRS'] = []
                        for addr in action.actual_addrs:
                            action_dict['DATA_ADDRS'].append(hex(addr))
                    if isinstance(action_data,list):
                        action_dict['DATA'] = repr(''.join(action_data))
                    else:
                        action_dict['DATA'] = repr(action_data)
                    corrupt_locations.append(action_dict)
    return corrupt_locations


def pretty_print(ref, type, value):
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    value = value.replace("CCCC", FAIL + "CCCC" + ENDC)
    value = value.replace("reboot", FAIL + "reboot" + ENDC)

    print_format = "{:<16} : {:<15} | {}"
    if ref.__class__ is not str and 'base' in ref.keys() and 'offset' in ref.keys():
        better_base = "{}+{}".format(ref['base'], ref['offset'])
        print(print_format.format(better_base, type, value))
    else:
        print(print_format.format(ref, type, value))


def get_ref_value(ref, type, value):
    if ref.__class__ is not str and 'base' in ref.keys() and 'offset' in ref.keys():
        better_base = "{}+{}".format(ref['base'], ref['offset'])
        return {
            "base" : better_base,
            "type" : type,
            "value" : value
        }
    else:
        return {
            "base" : ref,
            "type" : type,
            "value" : value
        }


def process(proj, simgr):
    return_dict = {}
    if "vulnerable" in simgr.stashes.keys():
        path = simgr.stashes['vulnerable'][0]

        return_dict['type'] = "Memory Corruption"

        return_dict['args'] = []
        for x, y, z in path.globals['args']:
            value = unravel(y, z, path)
            return_dict['args'].append(get_ref_value(x['ref'], str(y), value))
        return_dict['mem'] = get_corruption_location(proj, path)

        last_addr = [x for x in path.history.bbl_addrs][-1]

        desc_dict = {}
        desc_dict['BBL_ADDR'] = hex(last_addr)
        desc_dict['BBL_DESC'] = get_desc_and_dis(proj, last_addr)

        return_dict['DESC'] = desc_dict

    elif "exploitable" in simgr.stashes.keys() and len(simgr.stashes['exploitable']) > 0:
        path = simgr.stashes['exploitable'][0]
        return_dict['type'] = "Command Injection"

        val_loc = path.globals['val_offset']
        val_addr = path.globals['val_addr']
        solved_loc = hex(path.se.eval(val_loc))
        solved_addr = hex(path.se.eval(val_addr))

        return_dict['args'] = []
        for x, y, z in path.globals['args']:
            value = unravel(y, z, path)
            return_dict['args'].append(get_ref_value(x['ref'], str(y), value))

        temp = unravel(None, val_addr, path)
        return_dict['Injected_Location'] = get_ref_value(solved_addr, "char *", path.globals['cmd'])
        return_dict['Injected_Location']['Data'] = temp

        return_dict['mem'] = get_corruption_location(proj, path, path.globals['cmd'])

    return return_dict


def get_desc_and_dis(proj, address):
    ret_dict = {}
    ret_dict['DESCRIPTION'] = proj.loader.describe_addr(address)
    ret_dict['DISASSEMBLY'] = [str(x) for x in proj.factory.block(address).capstone.insns]
    return ret_dict


if __name__ == "__main__":
    main()
