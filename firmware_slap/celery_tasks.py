from celery import Celery
import tqdm
import os
import numpy as np
import matplotlib.pyplot as plt

from firmware_slap.function_analyzer import *
from firmware_slap import function_handler as fh
from firmware_slap import firmware_clustering as fhc
from firmware_slap import ghidra_handler as gh
from firmware_slap import celeryconfig as c_config

#angr logging is way too verbose
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

app = Celery('CeleryTask')
app.config_from_object(c_config)


@app.task
def async_trace_func(start_addr, args, file_name, ld_path, function_name=None):
    proj, simgr = do_trace(start_addr,
                           args,
                           file_name=file_name,
                           ld_path=ld_path)
    print(proj, simgr)
    ret_dict = process(proj, simgr)
    if ret_dict:
        ret_dict['file_name'] = file_name
        if function_name:
            ret_dict['func_name'] = function_name
        ret_dict['offset'] = start_addr
    return ret_dict


@app.task
def async_get_arg_funcs(file_name, use_ghidra=True):

    if use_ghidra:
        ret_list = gh.get_arg_funcs(file_name)
    else:
        ret_list = fh.get_arg_funcs(file_name)
    for func in ret_list:
        func['file_name'] = file_name
    return ret_list


@app.task
def async_get_funcs(file_name, use_ghidra=True):

    if use_ghidra:
        ret_list = gh.get_function_information(file_name)
    else:
        ret_list = fh.get_function_information(file_name)
    for func in ret_list:
        func['file_name'] = file_name
    return ret_list


@app.task
def async_get_single_cluster(all_functions, centroid_count):
    ret_dict = fhc.get_single_cluster(all_functions,
                                      centroid_count=centroid_count)
    ret_dict['labels'] = ret_dict['labels'].tolist()
    return ret_dict


@app.task
def async_get_sparse_file_data(file_name):
    return fhc.get_sparse_file_data(file_name)


@app.task
def async_trim_funcs(func_list, file_name):
    return fhc.trim_funcs(func_list, file_name=file_name)


def async_and_iter(async_function, async_list):

    async_funcs = []

    for item in async_list:
        n_task = async_function.delay(item)
        async_funcs.append(n_task)

    bar = tqdm.tqdm(total=len(async_funcs))
    while not all([x.ready() for x in async_funcs]):
        done_count = len([x.ready() for x in async_funcs if x.ready()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    return [x.get(propagate=False) for x in async_funcs if not x.failed()]


# TODO: Combine with above function
def async_and_iter_clusters(all_functions, max_centroid):

    async_funcs = []
    done_list = []

    for item in range(2, max_centroid):
        n_task = async_get_single_cluster.delay(all_functions, item)
        async_funcs.append(n_task)

    #bar = tqdm.tqdm(total=len(async_funcs))
    while not all([x.ready() for x in async_funcs]):
        done_count = len([x.ready() for x in async_funcs if x.ready()])
        done_list = check_iter_status(async_funcs, done_list)
        #bar.update(done_count - bar.n)

        time.sleep(.1)


#    bar.close()

    return [x.get(propagate=False) for x in async_funcs if not x.failed()]


def check_iter_status(async_items, done_list):

    ret = [
        x.get(propagate=False) for x in [y for y in async_items if y.ready()]
        if not x.failed()
    ]

    display_scores = False
    for item in ret:
        if item not in done_list:
            done_list.append(item)
            display_scores = True

    if display_scores:
        display_scores_list(done_list)

    return done_list


def display_scores_list(done_list, per_row=2, plot_it=True):

    import subprocess
    subprocess.call(["clear"])

    print(
        colored("[+] Current cluster scores (Cluster Count, Cluster Score)",
                'white',
                attrs=['bold']))

    temp_list = sorted(done_list, key=lambda k: k['score'])

    iter_count = len(temp_list) / per_row

    format_item = " {:<3} : {:<6} |"

    item_iter = 0
    for item in temp_list:
        temp_string = format_item.format(item['count'], str(item['score'])[:6])
        print(temp_string, end=" ")
        if item_iter % per_row == 0:
            print()
        item_iter += 1
    print()

    if plot_it:
        plot_list = sorted(done_list, key=lambda k: k['count'])

        plt.ion()
        plt.show()
        plt.title("Function similarity by cluster count and Silhoette score")
        plt.xlabel("Cluster Centroid Count")
        plt.ylabel("Silhoette Score")
        plt.grid = True

        plt.plot([x['count'] for x in plot_list],
                 [x['score'] for x in plot_list])
        plt.draw()
        plt.pause(0.05)
        plt.clf()
