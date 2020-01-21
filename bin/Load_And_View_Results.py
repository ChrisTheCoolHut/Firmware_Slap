import pickle
import argparse
from elasticsearch import Elasticsearch
import IPython
import tqdm
import subprocess
import time

docker_pull_cmd = "docker pull nshou/elasticsearch-kibana"
docker_run_cmd = "docker run -d -p 9200:9200 -p 5601:5601 nshou/elasticsearch-kibana"
docker_check_cmd = "docker image ls"
docker_ps = "docker ps"
docker_stop = "docker stop {}"
kibana_url = 'http://127.0.0.1:5601/app/kibana'
open_url = 'xdg-open {}'

func_index = "functions"
vuln_index = "vulnerabilities"


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("Pickle")
    parser.add_argument("-s", "--stop", action='store_true', default=False)

    args = parser.parse_args()

    if not check_image():
        pull_docker()

    if is_running() or args.stop:
        stop_running()
        if args.stop:
            exit(0)

    start_docker()

    with open(args.Pickle, 'rb') as f:
        test = pickle.load(f)

    es = Elasticsearch()

    wait_until_reachable(es)

    create_index(es, func_index, True)
    create_index(es, vuln_index, True)

    for func in tqdm.tqdm(test, total=len(test)):
        send_data(es, func)

    open_kibana()


def open_kibana():
    open_cmd = open_url.format(kibana_url)
    subprocess.check_call(open_cmd, shell=True)


def is_running():
    print("Checking if already running")
    p = subprocess.Popen(docker_ps, stdout=subprocess.PIPE, shell=True)
    cmd_output = p.communicate()[0]

    return b'nshou/elasticsearch-kibana' in cmd_output


def stop_running():
    p = subprocess.Popen(docker_ps, stdout=subprocess.PIPE, shell=True)
    cmd_output = p.communicate()[0]

    for line in cmd_output.splitlines():
        if b'nshou/elasticsearch-kibana' in line:
            docker_id = line.split()[0].decode('utf-8')

            print("Stopping ID {}".format(docker_id))
            stop_cmd = docker_stop.format(docker_id)
            subprocess.check_call(stop_cmd, shell=True)
            break


def check_image():
    print("Checking for existing image")
    p = subprocess.Popen(docker_check_cmd, stdout=subprocess.PIPE, shell=True)
    cmd_output = p.communicate()[0]

    return b'nshou/elasticsearch-kibana' in cmd_output


def pull_docker():
    print("Pulling docker")
    subprocess.check_call(docker_pull_cmd, shell=True)


def start_docker():
    print("Starting docker")
    subprocess.check_call(docker_run_cmd, shell=True)


def send_data(es, func):
    # Fix up function
    if 'task' in func.keys():
        func.pop('task')
    es.index(index=func_index, doc_type='external', body=func)
    if func['result']:
        es.index(index=vuln_index, doc_type='external', body=func)


def create_index(es, index_name, delete_if_exists=False):
    if delete_if_exists:
        if es.indices.exists(index_name):
            es.indices.delete(index=index_name)

    req_body = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}}

    if not es.indices.exists(index_name):
        es.indices.create(index=index_name, body=req_body)


def wait_until_reachable(es):
    if not es.ping():
        print("Waiting for Elasticsearch to become reachable")
        for count in range(6):
            time.sleep(10)
            if es.ping():
                return
        print("Error: Elasticsearch is unreachable")
        exit(1)


if __name__ == "__main__":
    main()
