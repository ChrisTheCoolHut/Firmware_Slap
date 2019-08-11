import r2pipe
import argparse
import IPython
from tqdm import tqdm

def get_function_information(file_name):
    func_list = []

    r2_ins = r2pipe.open(file_name, flags=["-2"])
    '''
    Commands = ['aa', 'afr', '& aap', '& aac', '& aar', '& aaE',
            '& aaf', '& aas', '& aae', '& aav', '&&', 'afva', 'afta']
    
    for command in tqdm(Commands, desc="Analysis Running"):
        r2_ins.cmd(command)
    '''

    r2_ins.cmd('aaa')
    try:
        func_list = r2_ins.cmdj('aflj')
    except:
        func_list = []
    r2_ins.quit()
    return func_list


def get_arg_funcs(file_name):
    return [x for x in get_function_information(file_name) if len(x) > 0 and 'nargs' in x.keys() and x['nargs'] > 0]


def get_base_addr(file_name):
    r2_ins = r2pipe.open(file_name, flags=["-2"])
    return r2_ins.cmdj('ij')['bin']['baddr']


def get_func_args(func):
    arg_list = []
    for var in (func['bpvars'] + func['regvars']):
        if 'arg' in var['kind']:
            arg_list.append(var)
        elif 'arg' in var['name'] and 'reg' in var['kind']:
            arg_list.append(var)
    return arg_list


def test():
    parser = argparse.ArgumentParser()

    parser.add_argument("File")

    args = parser.parse_args()

    info = get_function_information(args.File)

    arg_funcs = [x for x in info if x['nargs'] > 0]

    IPython.embed()

if __name__ == "__main__":
    test()
