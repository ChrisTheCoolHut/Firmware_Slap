#!/usr/bin/env python

from celery import Celery
import os

from firmware_slap.function_analyzer import *
from firmware_slap.celery_tasks import *
from firmware_slap import function_handler as fh
from firmware_slap import firmware_clustering as fhc
import Vuln_Discover_Celery as vd
import copy

#angr logging is way too verbose
import logging
import tqdm
import pickle
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False


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

    all_files = executables
    #all_files = executables + shared_libs

    # all_arg_funcs = async_and_iter(async_get_arg_funcs, all_files)

    if args.Vuln_Pickle:
        with open(args.Vuln_Pickle, 'rb') as f:
            file_vulnerabilities = pickle.load(f)
        pass
    else:
        file_vulnerabilities = vd.process_file_or_folder(
            args.Directory, args.LD_PATH)
        with open('cluster_pickle', 'wb') as f:
            pickle.dump(file_vulnerabilities, f, -1)

    print("[+] Getting sparse functions")

    all_functions = []
    all_trim_funcs = []

    for function_list in async_and_iter(async_get_sparse_file_data, all_files):
        all_functions.extend(copy.deepcopy(function_list))
        all_trim_funcs.extend(
            fhc.trim_funcs(function_list, function_list[0]['file_name']))

    all_functions = fhc.remove_non_needed_functions(all_functions,
                                                    remove_features=False)
    all_trim_funcs = fhc.remove_non_needed_functions(all_trim_funcs)

    print("[+] Clustering and scoring centroid counts")
    all_scores = async_and_iter_clusters(all_trim_funcs, 50)

    largest_dif = 200
    large_index = 0
    for x in range(1, len(all_scores) - 2):
        if largest_dif > all_scores[x]['score']:
            largest_dif = all_scores[x]['score']
            large_index = x
        '''
        if largest_dif < abs(scores[x] - scores[x+1]):
                largest_dif = abs(scores[x] - scores[x+1])
                large_index = x+1
        '''
    print("Largest drop at {} with {}".format(all_scores[large_index]['count'],
                                              largest_dif))

    Largest_Score_Drop = all_scores[large_index]
    function_distances = fhc.get_cosine_dist(all_trim_funcs)

    if args.Function:
        bugs = [x for x in file_vulnerabilities if args.Function in x['name']]
    else:
        bugs = [x for x in file_vulnerabilities if x['result']]

    for file_vuln in bugs:
        vuln_index = get_function_index(file_vuln, all_functions)
        if vuln_index is None:
            continue
        vuln_cluster = Largest_Score_Drop['labels'][vuln_index]
        similar_list = get_functions_on_cluster(all_functions, vuln_cluster,
                                                Largest_Score_Drop['labels'])

        reduced_list = []
        for func in similar_list:
            func_distance = get_func_dist(file_vuln, func, function_distances,
                                          all_functions)
            reduced_list.append({
                'file_name': func['file_name'],
                'func_name': func['name'],
                'distance': func_distance
            })

        reduced_list = sorted(reduced_list, key=lambda x: x['distance'])
        file_vuln['Similar_Funcs'] = reduced_list

    if bugs:
        print_function(bugs[0])


def get_func_dist(base_function, compare_function, distance_matrix,
                  all_functions):

    base_index = get_function_index(base_function, all_functions)
    comp_index = get_function_index(compare_function, all_functions)

    if base_index and comp_index:
        return distance_matrix[base_index][comp_index]
    else:
        return 0xFFFF


def get_functions_on_cluster(all_functions, centroid_number, labels):
    ret_list = []
    for x in range(len(all_functions)):
        if labels[x] == centroid_number:
            ret_list.append(all_functions[x])
    return ret_list


def get_function_index(file_vuln, all_functions):
    for x in range(len(all_functions)):
        func = all_functions[x]
        if 'offset' in all_functions[x].keys():
            if file_vuln['offset'] == all_functions[x]['offset']:
                if os.path.basename(
                        file_vuln['file_name']) == os.path.basename(
                            func['file_name']):
                    return x
    return None


def print_function(func):
    prototype = func['HiFuncProto']
    code = func['c_code']
    file_name = func['file_name']
    func_name = func['name']
    bug = func['result']
    bug_type = bug['type']
    print(
        colored("{} in {} at {}".format(bug_type, file_name, func_name),
                'red',
                attrs=['bold']))

    import re
    print(colored(prototype, 'cyan', attrs=['bold']))
    for arg in bug['args']:
        data = arg['value']
        data = re.sub('\\\\x[0-9][0-9]', '', data)
        print(
            colored("\t{} : {}".format(arg['base'], data),
                    'white',
                    attrs=['bold']))
    if 'Injected_Location' in bug.keys():
        print(colored("Injected Memory Location", 'cyan', attrs=['bold']))

        data = bug['Injected_Location']['Data']
        data = re.sub('\\\\x[0-9][0-9]', '', data)

        print(colored("\t{}".format(data), 'white', attrs=['bold']))
    print(colored("Tainted memory values", 'cyan', attrs=['bold']))
    for mem_val in bug['mem']:
        print(
            colored("{}".format(mem_val['BBL_DESC']['DESCRIPTION']),
                    'yellow',
                    attrs=['bold']))
        print(
            colored("\tMemory load addr {}".format(mem_val['DATA_ADDRS'][0]),
                    'white',
                    attrs=['bold']))
        data = re.sub('\\\\x[0-9][0-9]', '', mem_val['DATA'])
        print(
            colored("\tMemory load value {}".format(data),
                    'white',
                    attrs=['bold']))
        print()
    if 'Similar_Funcs' in func.keys():
        print(
            colored("Similar Functions With Distances",
                    'magenta',
                    attrs=['bold']))
        for sim_func in func['Similar_Funcs']:
            loc_string = "{:<30} in {}".format(
                sim_func['func_name'], sim_func['file_name'].split('/')[-1])
            print(colored(loc_string, 'blue', attrs=['bold']))
            dist_string = "\t> {}".format(sim_func['distance'])
            print(colored(dist_string, 'white', attrs=['bold']))


if __name__ == "__main__":
    main()
