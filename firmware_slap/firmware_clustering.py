import magic
import pickle
import argparse
import IPython
from multiprocessing import Pool
from tqdm import tqdm
#from function_clustering import funcs_to_sparse, trim_funcs
from .function_clustering import *
from .function_handler import get_arg_funcs, get_function_information
import matplotlib.pyplot as plt
from sklearn.metrics import silhouette_score
from sklearn.feature_extraction import DictVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import Normalizer
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_distances
import os
import hashlib

def get_executable_files(directory, progress=True):

    executables = []
    shared_libs = []
    hashes = []

    print("[+] Reading Files")
    if not os.path.isdir(directory):
        print("[~] {} is not directory".format(directory))
        file_type = magic.from_file(directory, mime=True)

        if "application/x-sharedlib" in file_type:
            shared_libs.append(directory)
        elif "symbolic link to" in file_type and ".so" in file_type:
            shared_libs.append(directory)
        elif "application/x-executable" in file_type:
            executables.append(directory)
    total_len = len([x for x in os.walk(directory)])
    for root, subdirs, files in tqdm(os.walk(directory), total=total_len):
        for filename in files:
            full_path = os.path.join(root, filename)

            #if os.path.islink(full_path):
            #    continue

            if os.path.isfile(full_path):
                file_type = magic.from_file(full_path, mime=True)

            if not os.path.islink(full_path):
                file_hash = md5sum(full_path)

            if file_hash not in hashes:
                hashes.append(file_hash)

                if "application/x-sharedlib" in file_type:
                    shared_libs.append(full_path)
                elif "symbolic link to" in file_type and ".so" in file_type:
                    shared_libs.append(full_path)
                elif "application/x-executable" in file_type:
                    executables.append(full_path)


    return executables,shared_libs

def md5sum(filename):
    h  = hashlib.md5()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def get_firmware_sparse(file_list):

    all_functions = []
    m_pool = Pool()

    print("[+] Getting Function Information")
    for i in tqdm(m_pool.imap_unordered(get_sparse_file_data, file_list), total=len(file_list)):
        all_functions.extend(i)

    '''
    for file_item in file_list:

        info = get_function_information(file_item)
        #arg_info = get_arg_funcs(file_item)
        #trimmed = trim_funcs(arg_info)
        trimmed = trim_funcs(info)
        all_functions.extend(trimmed)
    '''

    return all_functions


def get_sparse_file_data(file_name):

    info = get_function_information(file_name)
    #arg_info = get_arg_funcs(file_item)
    #trimmed = trim_funcs(arg_info)
    if info:
        trimmed = trim_funcs(info, file_name=file_name)
    else:
        trimmed = []
    return trimmed


def plot_clustering(all_functions, plot_it=False):
    vect, func_sparse = funcs_to_sparse(all_functions)

    transformer = Normalizer().fit(func_sparse)

    func_sparse = transformer.transform(func_sparse)

    #svd = TruncatedSVD(random_state=2)
    #svd = TruncatedSVD(n_components=5, n_iter=7, random_state=42)

    #func_sparse = svd.fit_transform(func_sparse)

    scores = []
    clust_count = []
    labels = []
    for x in range(2,50):
        result = KMeans(n_clusters=x, random_state=2).fit(func_sparse)

        score = silhouette_score(func_sparse, result.labels_, metric="cosine", random_state=2, sample_size=5000)
        scores.append(score)
        clust_count.append(x)
        labels.append(result.labels_)

        print("Clusters {:<3} | Silhoette Score : {}".format(x, score))

    largest_dif = 200
    large_index = 0
    for x in range(1,len(scores)-2):
        if largest_dif > scores[x]:
            largest_dif = scores[x]
            large_index = x
        '''
        if largest_dif < abs(scores[x] - scores[x+1]):
                largest_dif = abs(scores[x] - scores[x+1])
                large_index = x+1
        '''
    print("Largest drop at {} with {}".format(clust_count[large_index], largest_dif))

    if plot_it:
        plt.plot(clust_count, scores)
        plt.xlabel("Cluster Centroid Count")
        plt.ylabel("Silhoette Score")
        plt.grid = True
        plt.show()

    return labels[large_index]


def single_cluster(all_functions, centroid_count=2):
        vect, func_sparse = funcs_to_sparse(all_functions)

        transformer = Normalizer().fit(func_sparse)

        func_sparse = transformer.transform(func_sparse)

        # svd = TruncatedSVD(random_state=2)
        # svd = TruncatedSVD(n_components=5, n_iter=7, random_state=42)

        # func_sparse = svd.fit_transform(func_sparse)

        labels = []

        result = KMeans(n_clusters=centroid_count, random_state=2).fit(func_sparse)

        score = silhouette_score(func_sparse, result.labels_, metric="cosine", random_state=2, sample_size=5000)
        labels.append(result.labels_)

        print("Clusters {:<3} | Silhoette Score : {}".format(centroid_count, score))

        return result.labels_

def get_cosine_dist(all_functions):
    return_dict = {}
    vect, func_sparse = funcs_to_sparse(all_functions)

    transformer = Normalizer().fit(func_sparse)

    func_sparse = transformer.transform(func_sparse)

    return cosine_distances(func_sparse, func_sparse)

def get_single_cluster(all_functions, centroid_count=2):
    return_dict = {}
    vect, func_sparse = funcs_to_sparse(all_functions)

    transformer = Normalizer().fit(func_sparse)

    func_sparse = transformer.transform(func_sparse)

    # svd = TruncatedSVD(random_state=2)
    # svd = TruncatedSVD(n_components=5, n_iter=7, random_state=42)

    # func_sparse = svd.fit_transform(func_sparse)

    labels = []

    result = KMeans(n_clusters=centroid_count, random_state=2).fit(func_sparse)

    score = silhouette_score(func_sparse, result.labels_, metric="cosine", random_state=2, sample_size=5000)
    labels.append(result.labels_)

    #print("Clusters {:<3} | Silhoette Score : {}".format(centroid_count, score))
    return_dict['count'] = centroid_count
    return_dict['score'] = score
    return_dict['labels'] = result.labels_

    return return_dict


def remove_non_needed_functions(all_functions, remove_features=True):

    bad_prefix = ["fcn.", "sub.", "loc.", "aav.",
                  "sym._fini", "sym._init"]

    keep_functions = []
    for function in all_functions:
        if not any(prefix in function['name'] for prefix in bad_prefix):
            keep_functions.append(function)

    if remove_features:
        bad_features = ['bits', 'calltype', 'maxbound', 'minbound', 'offset', 'size']
        for function in keep_functions:
            for feat in bad_features:
                try:
                    function.pop(feat)
                except:
                    pass

    return keep_functions


def test():
    parser = argparse.ArgumentParser()

    parser.add_argument("Directory")
    parser.add_argument("--Dump", "-D", help="Dump to pickle")
    parser.add_argument("--Load", "-L", help="Load from pickle")

    args = parser.parse_args()

    if args.Load:
        with open(args.Load, 'rb') as f:
            all_functions = pickle.load(f)
    else:
        executables,shared_libs = get_executable_files(args.Directory)

        all_files = executables + shared_libs

        all_functions = get_firmware_sparse(all_files)

        if args.Dump:
            with open(args.Dump, 'wb') as f:
                pickle.dump(all_functions, f, -1)

    #Fix symbols 'n stuff
    bad_prefix = ["fcn.", "sub.", "loc.", "aav.",
        "sym._fini", "sym._init"]
    all_functions = [x for x in all_functions if not any([y in x['name'] for y in bad_prefix])]

    bad_features = ['bits', 'calltype', 'maxbound', 'minbound', 'offset', 'size']
    for func in all_functions:
        for feat in bad_features:
            func.pop(feat)

    func_labels = plot_clustering(all_functions, True)

    file_names = [x['file_name'] for x in all_functions]
    func_names = [x['name'] for x in all_functions]
    for x,y,z in zip(file_names, func_names, func_labels):
        x = x.split('/')[-1]
        print("{} | {} | {}".format(x,y,z))

    IPython.embed()

if __name__ == "__main__":
    test()
