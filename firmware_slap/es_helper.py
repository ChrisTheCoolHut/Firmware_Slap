from elasticsearch import Elasticsearch
import IPython
import pickle
import argparse

es_host = "localhost"
es_port = 9200
vulnerability_index = "vulnerabilities"
function_index = "functions"


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Pickle_Obj")

    args = parser.parse_args()

    with open(args.Pickle_Obj, 'rb') as f:
        test = pickle.load(f)

    es = get_es()
    build_index(es, vulnerability_index, del_if_exists=True)
    build_index(es, function_index, del_if_exists=True)

    IPython.embed()


def import_list(es, index_name, nodes):
    for node in nodes:
        import_item(es, index_name, node)


def import_item(es, index_name, node):
    es.index(index=index_name, doc_type='external', body=node)


def get_es():
    return Elasticsearch([{
        'host': es_host,
        'port': es_port
    }],
                         timeout=30,
                         max_retries=10,
                         retry_on_timeout=True)


def search_index(es, index_name, file_name):
    return es.search(index=index_name,
                     body={"query": {
                         "match": {
                             "file_name": file_name
                         }
                     }})


def search_index_hash(es, index_name, file_hash):
    return es.search(index=index_name,
                     body={"query": {
                         "match": {
                             "func_hash": file_hash
                         }
                     }})


def build_index(es, i_name, del_if_exists=False):

    if es.indices.exists(i_name) and del_if_exists:
        print("Deleteing index by name {}".format(i_name))
        res = es.indices.delete(index=i_name)
        print(res)
    if not es.indices.exists(i_name):
        req_body = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        }
        print("Creating index by name {}".format(i_name))
        res = es.indices.create(index=i_name, body=req_body)


if __name__ == "__main__":
    main()
