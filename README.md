# Firmware Slap

Firmware slap combines concolic analysis with function clustering for vulnerability discovery and function similarity in firmware. Firmware slap is built as a series of libraries and exports most information as either pickles or JSON for integration with other tools.

![Firmware Slap](https://i.imgur.com/fxIIogI.gif)

Slides from the talk can be found [here](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Christopher-Roberts-Firmware-Slap.pdf)

## Setup

Firmware slap should be run in a virtual environment. It has been tested on Python3.6
```bash
sudo apt install python3-virtualenv
virtualenv -p python3 fwslap
source fwslap/bin/activate
```
-- or --

```bash
cd ~
mkdir .virtualenvs
pip install virtualenv
which virtualenv #note path warnings
pip install virtualenvwrapper
echo "export PATH=$PATH:~/.local/bin" >> ~/.bashrc
echo "export WORKON_HOME=~/.virtualenvs" >> ~/.bashrc
echo "source ~/.local/bin/virtualenvwrapper.sh" >> ~/.bashrc

#usually best here to open new terminal

mkvirtualenv fwslap -p /usr/bin/python3
workon fwslap
```


```bash
python setup.py install
```

You will need rabbitmq, docker, and (radare2 or Ghidra)
```bash
# Ubuntu
sudo apt install rabbitmq-server docker.io
# OSX
brew install rabbitmq

# Radare2
git clone https://github.com/radare/radare2.git
sudo ./radare2/sys/install.sh
# Ghidra
wget https://ghidra-sre.org/ghidra_9.0.4_PUBLIC_20190516.zip
unzip ghidra_9.0.4_PUBLIC_20190516.zip -d ghidra
echo "export PATH=\$PATH:$PWD/ghidra/ghidra_9.0.4/support" >> ~/.bashrc
```

Ghidra requires JDK 11.
```bash
sudo apt install default-jdk
java --version
```

If you want to use the Elastic search stuff run the `Elasticsearch_and_kibana.sh` script

## Quickstart

Ensure rabbitmq-server is running.

```bash
# In a Separate terminal, run this in the top level "Firmware_Slap" directory
celery -A firmware_slap.celery_tasks worker --loglevel=info
# Basic buffer overflow
Discover_And_Dump.py examples/iwconfig -D iwconfig_results
Load_And_View_Results.py iwconfig_results.all.pickle

# Click management on the left pane
# Click Saved Objects
# Click Import
# Select 'elastic_export.json' under the elastic directory in firmware slap
# Navigate to dashboards on left pane and select 'Overview Dashboard'

Load_And_View_Results.py iwconfig_results.all.pickle -s

# Command injection
tar -xvf examples/Almond_libs.tar.gz
Vuln_Discover_Celery.py examples/upload.cgi -L Almond_Root/lib/
```

## Usage

```bash
# Get the firmware used for examples
wget https://firmware.securifi.com/AL3_64MB/AL3-R024-64MB
binwalk -Mre AL3-R024-64MB
```

Start a celery work from the project root directory:
```bash
# In a separate terminal
celery -A firmware_slap.celery_tasks worker --loglevel=info
```

In a different terminal window, run a vulnerability discovery job.

```bash
$ Vuln_Discover_Celery.py Almond_Root/etc_ro/lighttpd/www/cgi-bin/upload_bootloader.cgi -L Almond_Root/lib/
[+] Getting argument functions
[+] Analyzing 1 functions
  0%|                                                                                                                                                                                                                                   | 0/1 [00:01<?, ?it/s]
{   'Injected_Location': {   'base': '0x7ffefde8',
........................ SNIP ......................
    'type': 'Command Injection'}
Python 3.5.2 (default, Nov 12 2018, 13:43:14) 
Type 'copyright', 'credits' or 'license' for more information
IPython 7.3.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: 
```

## The returned vulnerability object

The above command will return an object in the `result` variable. This is a dictionary will all sorts of awesome information about the vulnerability. There are three major keys in the object: The function arguments, The memory, and the injected location.
```
In [3]: result.keys()                                                                                 
Out[3]: dict_keys(['args', 'file_name', 'type', 'mem', 'Injected_Location'])
```
### args
The args key will detail information about the recovered argument and what the argument values must be to recreate the vulnerability. In the below example, one argument is recovered, and to trigger the command injection that argument must be a char* that contains "\`reboot\`" to trigger a reboot.
```
In [1]: result['args']                                                           
Out[1]: 
[{'base': 'a1',
  'type': 'int',
  'value': "0x0 -> b'`reboot`\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x00'"}]
```

### Memory
The memory component of the object keeps track of the required memory values set to trigger the vulnerability. It also offers stack addresses and .text addresses with the offending commands for setting the required memory constraints. The first memory event required is at `mtd_write_firmware+0x0` and the second is at `mtd_write_firmware+0x38`. Assembly is provided to help prettify future display work.
```
In [2]: result['mem']                                                                   
Out[2]: 
[{'BBL_ADDR': '0x401138',
  'BBL_DESC': {'DESCRIPTION': 'mtd_write_firmware+0x0 in upload_bootloader.cgi (0x401138)',
   'DISASSEMBLY': ['0x401138:\tlui\t$gp, 0x42',
    '0x40113c:\taddiu\t$sp, $sp, -0x228',
    '0x401140:\taddiu\t$gp, $gp, -0x5e90',
    '0x401144:\tlw\t$t9, -0x7f84($gp)',
    '0x401148:\tsw\t$a2, 0x10($sp)',
    '0x40114c:\tlui\t$a2, 0x40',
    '0x401150:\tmove\t$a3, $a1',
    '0x401154:\tsw\t$ra, 0x224($sp)',
    '0x401158:\tsw\t$gp, 0x18($sp)',
    '0x40115c:\tsw\t$a0, 0x14($sp)',
    '0x401160:\taddiu\t$a1, $zero, 0x200',
    '0x401164:\taddiu\t$a0, $sp, 0x20',
    '0x401168:\tjalr\t$t9',
    '0x40116c:\taddiu\t$a2, $a2, 0x196c']},
  'DATA': "b'`reboot`\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'",
  'DATA_ADDRS': ['0x0']},
 {'BBL_ADDR': '0x401170',
  'BBL_DESC': {'DESCRIPTION': 'mtd_write_firmware+0x38 in upload_bootloader.cgi (0x401170)',
   'DISASSEMBLY': ['0x401170:\tlw\t$gp, 0x18($sp)',
    '0x401174:\tnop\t',
    '0x401178:\tlw\t$t9, -0x7f68($gp)',
    '0x40117c:\tnop\t',
    '0x401180:\tjalr\t$t9',
    '0x401184:\taddiu\t$a0, $sp, 0x20']},
  'DATA': "b'/bin/mtd_write -o 0 -l 0 write `reboot`'",
  'DATA_ADDRS': ['0x7ffefe07']}]
```
### Command Injection Specific
Since command injections are the easiest to demo, I've created a convenience dictionary key to demonstrate the location of the command injection easily.
```
In [4]: result['Injected_Location']                                                                      
Out[4]: {'base': '0x7ffefde8', 'type': 'char *', 'value': '/bin/mtd_write -o 0 -l 0 write `reboot`'}
```

### Sample Vulnerability Cluster Script
The vulnerability cluster script will attempt to discover vulnerabilities using the method in the Sample Vulnerability Discovery script and then build k-means clusters of a set of given functions across an extracted firmware to find similar functions to vulnerable ones.
```bash
$ Vuln_Cluster_Celery.py -h
usage: Vuln_Cluster_Celery.py [-h] [-L LD_PATH] [-F FUNCTION] [-V VULN_PICKLE]
                              Directory

positional arguments:
  Directory

optional arguments:
  -h, --help            show this help message and exit
  -L LD_PATH, --LD_PATH LD_PATH
                        Path to libraries to load
  -F FUNCTION, --Function FUNCTION
  -V VULN_PICKLE, --Vuln_Pickle VULN_PICKLE

```
The below command takes -F as a known vulnerable function. -V as a dumped pickle from a previous run  to not need to discover new vulnerabilites and -L for the library path.
A sample usage:

```bash
$ python Vuln_Cluster_Celery.py -F mtd_write_firmware -L Almond_Root/lib/ Almond_Root/etc_ro/lighttpd/www/cgi-bin/
[+] Reading Files
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  2.80it/s]
Getting functions from executables
Starting main
... Snip ...

```
 
