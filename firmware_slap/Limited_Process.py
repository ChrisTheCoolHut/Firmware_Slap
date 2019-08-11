import psutil
import os
import signal
import multiprocessing
import time
class Limited_Process:
    def __init__(self, proc, function, time_limit, mem_limit, proc_queue):
        self.proc = proc
        self.function = function
        self.start_time = time.time()
        self.time_limit = time_limit
        self.mem_limit = mem_limit
        self.proc_queue = proc_queue
        self.finished = False

    def get_memory_usage(self):
        try:
            psutil_proc = psutil.Process(self.proc.pid)
        except psutil._exceptions.NoSuchProcess as e:
            self.finished = True
            return 0
        except AttributeError as e:
            psutil_proc = psutil.Process(os.getpid())
            
        return psutil_proc.memory_info().rss / (1024 * 1024)

    def mem_overused(self):
        return self.get_memory_usage() > self.mem_limit

    def time_is_up(self):
        curr_time = time.time()
        time_diff = int(curr_time - self.start_time)
        return time_diff > self.time_limit

    def get(self):
        try:
            return self.proc_queue.get(timeout=.1)
        except:
            return "timeout"
        '''
        except multiprocessing.context.TimeoutError as e:
            return "timeout"
        except multiprocessing.queues.Empty as e:
            return "timeout"
        '''


    def die(self):
        try:
            os.kill(self.proc.pid, signal.SIGKILL)
        except:
            self.finished = True
        #self.proc.terminate()

