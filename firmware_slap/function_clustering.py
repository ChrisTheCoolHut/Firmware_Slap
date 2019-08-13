import IPython
import argparse
from tqdm import tqdm
from firmware_slap import function_handler as fh
import matplotlib.pyplot as plt
from sklearn.metrics import silhouette_score
from sklearn.feature_extraction import DictVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import Normalizer
from sklearn.cluster import KMeans


def funcs_to_sparse(func_list):
    vectorizor = DictVectorizer()
    func_sparse = vectorizor.fit_transform(func_list)
    return vectorizor, func_sparse


def trim_funcs(func_list, file_name=""):

    use_call_type = False
    #for func in tqdm(func_list, desc="Trimming Functions"):
    to_remove = []
    for func in func_list:

        if 'file_name' not in func.keys():
            func['file_name'] = file_name

        trim_import = True
        if trim_import:
            if "sym.imp" in func['name']:
                to_remove.append(func)
                continue
        only_symbols = True
        if only_symbols:
            bad_prefix = [
                "fcn.", "sub.", "loc.", "aav.", "sym._fini", "sym._init"
            ]
            if any([x in func['name'] for x in bad_prefix]):
                to_remove.append(func)
                continue

        #codexrefs
        if "codexrefs" in func.keys():
            for ref in func['codexrefs']:

                if use_call_type:
                    #Define jump or call
                    my_str = str(ref['addr']) + str(ref['at']) + str(
                        ref['type'])
                else:
                    #Ignore ref type
                    my_str = str(ref['addr']) + str(ref['at'])
                my_str += "xref"
                func[my_str] = 1
            func.pop('codexrefs')

        #callrefs
        if "callrefs" in func.keys():
            for ref in func['callrefs']:
                if use_call_type:
                    #Define jump or call
                    my_str = str(ref['addr']) + str(ref['at']) + str(
                        ref['type'])
                else:
                    #Ignore ref type
                    my_str = str(ref['addr']) + str(ref['at'])
                my_str += "cref"
                func[my_str] = 1
            func.pop('callrefs')

        #bpvars
        if "bpvars" in func.keys():
            for bpvar in func['bpvars']:
                kind = bpvar['kind']
                ref = str(bpvar['ref']['base']) + str(bpvar['ref']['offset'])
                v_type = bpvar['type']
                my_str = kind + ref + v_type
                func[my_str] = 1
            func.pop('bpvars')

        remove_list = []
        #Everything else
        for k, v in func.items():
            if type(v) == list:
                remove_list.append(k)
                #func.pop(k)

        for item in remove_list:
            func.pop(item)

    #Remove imports
    for item in to_remove:
        func_list.remove(item)

    return func_list


def test():
    parser = argparse.ArgumentParser()

    parser.add_argument("File")

    args = parser.parse_args()

    info = fh.get_function_information(args.File)
    #info = fh.get_arg_funcs(args.File)

    info = trim_funcs(info, args.File)

    vect, func_sparse = funcs_to_sparse(info)

    transformer = Normalizer().fit(func_sparse)

    func_sparse = transformer.transform(func_sparse)

    #svd = TruncatedSVD(random_state=2)
    svd = TruncatedSVD(n_components=5, n_iter=7, random_state=42)

    func_sparse = svd.fit_transform(func_sparse)

    scores = []
    clust_count = []
    for x in range(2, 20):
        result = KMeans(n_clusters=x, random_state=2).fit(func_sparse)

        score = silhouette_score(func_sparse, result.labels_, metric="cosine")
        scores.append(score)
        clust_count.append(x)

        print("Clusters {:<3} | Silhoette Score : {}".format(x, score))

    plt.plot(clust_count, scores)
    plt.xlabel("Cluster Centroid Count")
    plt.ylabel("Silhoette Score")
    plt.grid = True
    plt.show()

    pass


if __name__ == "__main__":
    test()
