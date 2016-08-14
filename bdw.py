import threading
import sys
import pcapy
import time
import logging as logger

class NetMonitor(threading.Thread):

    _timeout = 1

    @classmethod
    def get_net_interfaces(cls):
        return pcapy.findalldevs()

    def __init__(self, device, bpf_filter):
        threading.Thread.__init__(self)

        self.active = True
        self._net_monitor = pcapy.open_live(device, 65535, 0, 1000) #self.timeout * 1000)
        self._net_monitor.setfilter(bpf_filter)
        #self.dumper = self.net_monitor.dump_open("pkt_dump.txt")

        self._current_bytes_rate = 0
        self.total_transfer = 0 # total number of Bytes transfered

        #<--- this is to calc average transfer B/s
        self._tmp_bytes_per_sec_sum = 0 # sums up B/s values from each dispatch iteration (eventually used to calc average value)
        self._inc = 0 # number of dispatch iterations (eventually used to calc average B/s value)
        #--->

        self._dispatch_bytes_sum = 0 # sums up packets size for one dispatch call


    def __handle_packet(self, header, data):
        # method is called for each packet by dispatch call (pcapy)
        self._dispatch_bytes_sum += len(data) #header.getlen() #len(data)
        #logger.debug("h: ({}, {}, {}), d:{}".format(header.getlen(), header.getcaplen(), header.getts(), len(data)))
        #self.dumper.dump(header, data)


    def update(self):
        self._dispatch_bytes_sum = 0
        # process packets
        packets_nr = self._net_monitor.dispatch(-1, self.__handle_packet)
        self.total_transfer += self._dispatch_bytes_sum

        self._inc += 1
        self._current_bytes_rate = self._dispatch_bytes_sum  # add single dispatch B/s -> timeout is 1 s
        self._tmp_bytes_per_sec_sum += self._current_bytes_rate

        logger.debug('inc:{}, current rate: {} B/s, avg rate: {} B/s,  total:{} B'.format(self._inc, self.current_rate, self.avg_rate, self.total_transfer))

        return self._current_bytes_rate, packets_nr



    def get_avg_bytes_rate(self):
        if self._inc:
            return self._tmp_bytes_per_sec_sum / self._inc
        else:
            return 0

    def get_current_bytes_rate(self):
        return self._current_bytes_rate


    def run(self):
        while(self.active):
            self.update()
            time.sleep(self._timeout)


    # average B/s rate
    avg_rate = property(get_avg_bytes_rate)
    # current B/s rate
    current_rate = property(get_current_bytes_rate)





if __name__ == '__main__':

    filter = ' '.join(sys.argv[2:])
    print filter
    #nm0 = NetMonitor(pcapy.findalldevs()[0], filter)
    nm1 = NetMonitor(pcapy.findalldevs()[1], filter)

    nm1.start()
    start_time = time.time()
    while time.time() - start_time < int(sys.argv[1]):
        print "current {} B/s, avg {} B/s, total transfer {} B".format(nm1.current_rate, nm1.avg_rate, nm1.total_transfer)
        time.sleep(1)

    nm1.active = False
    nm1.join()

    print "++++++ total: {}, avg: {}".format(nm1.total_transfer, nm1.avg_rate)
