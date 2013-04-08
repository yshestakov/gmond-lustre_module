#!/usr/bin/env python2.6
#
# Description: Lustre monitoring for Ganglia
# Author: Yuriy Shestakov <yshestakov@gmail.com>
# Date: 2013-04-08
# License: LGPL

import sys
import os
import time
import logging
import socket
import re
from logging.handlers import SysLogHandler


LUSTRE_VERSION_FN = '/proc/fs/lustre/version'
LUSTRE_DEVICES_FN = '/proc/fs/lustre/devices'
LUSTRE_OST_DIR = '/proc/fs/lustre/obdfilter'
LUSTRE_MDT_DIR = '/proc/fs/lustre/mdt'
LUSTRE_MGS_DIR = '/proc/fs/lustre/mgs/MGS'
LUSTRE_MDC_DIR = '/proc/fs/lustre/mdc'
LUSTRE_OSC_DIR = '/proc/fs/lustre/osc'
LUSTRE_OSS_DIR = '/proc/fs/lustre/ost/OSS/ost'


class SafeSyslogHandler(SysLogHandler):
    def _connect_unixsocket(self, address):
        try:
            SysLogHandler._connect_unixsocket(self, address)
        except socket.error, err:
            sys.stderr.write("Can't connect to unix socket %s: %s\n" % (address, err))


def init_logger(who='gmond-lustre'):
    logger = logging.getLogger(who)  # ("scheduler")
    logger.setLevel(logging.DEBUG)

    if sys.platform == 'linux2':
        log_path = '/dev/log'
    else:
        raise RuntimeError('Unknown platform. linux2 is supported only')

    if not os.path.exists(log_path):
        hdlr = logging.StreamHandler()
    else:
        hdlr = SafeSyslogHandler(address=log_path,
                                 facility=SysLogHandler.LOG_DAEMON)
    #formatter = logging.Formatter('%(filename)s: %(levelname)s: %(message)s')
    formatter = logging.Formatter('%(filename)s: %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    #logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s\t"
    #                    " Thread-%(thread)d - %(message)s", filename='/tmp/gmond-lustre.log', filemode='w')
    #logging.debug('starting up')
    logger.debug('starting up')
    return logger

logger = init_logger()


def _get_num_refs(dir):
    "Return content of {dir}/nun_refs"
    num_refs_fn = os.path.join(dir, 'num_refs')
    if not os.path.exists(num_refs_fn):
        return None
    ret = None
    with open(num_refs_fn, 'r') as fi:
        ret = int(fi.read())
        fi.close()
    return ret


class LustreStatsSnapshot(object):
    "LustreStatsSnapshot handles metrics for MGS, MDT and OST targets"

    def __init__(self, proc_dir, stats_fn='stats'):
        "Constructor"
        self.stats_fn = os.path.join(proc_dir, stats_fn)
        self.name_map = dict()
        self.units_map = dict()
        self.snapshot = []
        self.timestamp = None
        logger.debug("LustreStatsSnapshot: stats_fn is %s" % self.stats_fn)
        fi = open(self.stats_fn, 'r')
        for idx, line in enumerate(fi.readlines()):
            ary = re.split('\s+', line)
            if idx == 0:
                sec, usec = ary[1].split('.')
                self.timestamp = long(sec)
                self.timestamp_usec = int(usec)
                self.snapshot.append(float(ary[1]))
            else:
                self.name_map[ary[0]] = idx
                self.units_map[ary[0]] = ary[3]
                self.snapshot.append(long(ary[1]))
        fi.close()

    def update(self, m_prefix, m_handler):
        "re-read metrics from the file and update m_nadler.info dictionary"
        snapshot = []
        fi = open(self.stats_fn, 'r')
        delta_t = 1.0
        for idx, line in enumerate(fi.readlines()):
            ary = re.split('\s+', line)
            if idx == 0:
                sec, usec = ary[1].split('.')
                self.timestamp = long(sec)
                self.timestamp_usec = int(usec)
                ts = float(ary[1])
                delta_t = ts - self.snapshot[0]
                snapshot.append(ts)
            else:
                name = ary[0]  # parameter name
                c_val = long(ary[1])  # current value
                snapshot.append(c_val)
                m_name = '%s.%s' % (m_prefix, name)
                try:
                    diff = c_val - self.snapshot[idx]
                except IndexError:
                    diff = c_val
                if diff < 0:
                    diff += 4294967296L
                m_handler.info[m_name] = int(diff / delta_t)
        fi.close()
        self.snapshot = snapshot

    def add_metrics(self, metrics, prefix):
        "Dynamically add metrics for the :dict:`metrics`"
        for name in self.name_map.keys():
            m_name = '%s.%s' % (prefix, name)
            metrics[m_name] = {
                # 'units': self.units_map[name],
                'units': 'req/s',
                'description': 'Lustre target stats'
            }

    def __str__(self):
        return "<LustreStatsSnapshot(%r)>" % self.__dict__


class LustreDevice(object):

    def __init__(self, state, name, uuid):
        self.name = name
        self.uuid = uuid
        self.state = state
        self.stats = None

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.%s' % self.name

    def stats_update(self, m_handler):
        "Call stats.update() to update m_handler.info dict"
        self.stats.update(self.m_prefix(), m_handler)

    def add_metrics(self, metrics):
        "Add metrics to the metrics dict"
        if self.stats:
            self.stats.add_metrics(metrics, self.m_prefix())


class MGS(LustreDevice):

    def __init__(self, state, name, uuid):
        super(MGS, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(os.path.join(LUSTRE_MGS_DIR, 'mgs'))

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.mgs'


class MDT(LustreDevice):

    def __init__(self, state, name, uuid):
        super(MDT, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(os.path.join(LUSTRE_MDT_DIR, name, 'mdt'))
        self.md_stats = LustreStatsSnapshot(os.path.join(LUSTRE_MDT_DIR, name), stats_fn='md_stats')

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.mdt.%s' % self.name

    def __str__(self):
        return "<MDT(%r)>" % self.__dict__

    def stats_update(self, m_handler):
        "Call stats.update() to update m_handler.info dict"
        m_prefix = self.m_prefix()
        self.stats.update(m_prefix, m_handler)
        self.md_stats.update(m_prefix, m_handler)

    def add_metrics(self, metrics):
        "Add metrics to the metrics dict"
        super(MDT, self).add_metrics(metrics)
        if self.md_stats:
            self.md_stats.add_metrics(metrics, self.m_prefix())


class MDC(LustreDevice):

    def __init__(self, state, name, uuid):
        super(MDC, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(os.path.join(LUSTRE_MDC_DIR, name))

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.mdc.%s' % self.name


class OSC(LustreDevice):

    def __init__(self, state, name, uuid):
        super(OSC, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(os.path.join(LUSTRE_OSC_DIR, name))

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.osc.%s' % self.name


class OST(LustreDevice):

    def __init__(self, state, name, uuid):
        super(OST, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(os.path.join(LUSTRE_OST_DIR, name))

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.ost.%s' % self.name


class OSS(LustreDevice):

    def __init__(self, state, name, uuid):
        super(OSS, self).__init__(state, name, uuid)
        self.stats = LustreStatsSnapshot(LUSTRE_OSS_DIR)

    def m_prefix(self):
        "Metric name prefix"
        return 'lustre.oss'


class LustreMetrics(object):
    "LustreMetrics class is the Ganglia metrics module"

    obj = None  # instance of the LustreMetrics class

    def __init__(self):
        "Constructor, should not do any I/O"
        self.timestamp = 0
        self.fs_name = None
        self.report_mds = False
        self.report_oss = False
        self.report_osc = False
        self.info = {}
        self.devices = []
        self.descriptors = {}

    def set_params(self, params):
        "Set metrics parameters passed from gmond config (lustre.pyconf)"
        self.report_mds = str(params.get('report_mds', True)) == "True"
        self.report_oss = str(params.get('report_oss', True)) == "True"
        self.report_osc = str(params.get('report_osc', True)) == "True"
        self.fs_name = params.get('fs_name', '')

    def handler(self, name):
        "The value of the name parameter will be the name of the metric that is being gathered."

        # Don't thrash.
        now = time.time()
        if 5 < now - self.timestamp:
            try:
                self.read_dev_stats()
            except Exception, exc:
                logger.error("LustreMetrics.handler error: %s" % exc)
            self.timestamp = now
        # logger.debug("returning metric_handle: %s %s" % (name, self.info.get(name, 0)))
        return self.info.get(name, 0)

    def get_lustre_version(self):
        "Check /proc/fs/lustre/version file"
        if not os.path.exists(LUSTRE_VERSION_FN):
            return False
        with open(LUSTRE_VERSION_FN, 'r') as fi:
            for line in fi.readlines():
                key, val = line.strip().split(': ')
                if key == 'lustre':
                    self.info['lustre.version'] = val
                elif key == 'build':
                    self.info['lustre.kernel_build'] = val
            fi.close()
        self.info['lustre.is_mgs'] = os.path.exists(LUSTRE_MGS_DIR)
        return True

    def read_dev_stats(self):
        "Read .../stats file for LustreDevices objects in the self.devices"
        for dev in self.devices:
            dev.stats_update(self)

    def get_lustre_devices(self):
        "Read /proc/fs/lustre/devices file"
        if not os.path.exists(LUSTRE_DEVICES_FN):
            return False
        devs = []
        self.info['lustre.mgc_count'] = 0
        self.info['lustre.mdc_count'] = 0
        self.info['lustre.mdt_count'] = 0
        self.info['lustre.ost_count'] = 0
        self.info['lustre.osc_count'] = 0
        self.info['lustre.lov_count'] = 0
        self.info['lustre.lmv_count'] = 0
        with open(LUSTRE_DEVICES_FN, 'r') as fi:
            for line in fi.readlines():
                (id, state, thr, dev_name, dev_uuid, foo) = line.strip().split(' ')
                if thr == 'mgc':  # connection to MGS
                    self.info['lustre.mgc_count'] += 1
                elif thr == 'mgs':  # MGS
                    dev = MGS(state=state, name=dev_name, uuid=dev_uuid)
                    devs.append(dev)
                elif thr == 'mdt':  # meta data target
                    if self.report_mds:
                        dev = MDT(state=state, name=dev_name, uuid=dev_uuid)
                        devs.append(dev)
                    self.info['lustre.mdt_count'] += 1
                elif thr == 'mds':
                    pass
                elif thr == 'mdc':  # meta data client (connects over network to MDT)
                    dev = MDC(state=state, name=dev_name, uuid=dev_uuid)
                    devs.append(dev)
                    self.info['lustre.mdc_count'] += 1
                elif thr == 'osc':  # object storage client (connects over network to OST)
                    if self.report_osc:
                        dev = OSC(state=state, name=dev_name, uuid=dev_uuid)
                        devs.append(dev)
                    self.info['lustre.osc_count'] += 1
                elif thr == 'ost':  # object storage target
                    if self.report_oss:
                        dev = OSS(state=state, name=dev_name, uuid=dev_uuid)
                        devs.append(dev)
                elif thr == 'obdfilter':  # OST target thread
                    if self.report_oss:
                        dev = OST(state=state, name=dev_name, uuid=dev_uuid)
                        devs.append(dev)
                    self.info['lustre.ost_count'] += 1
                elif thr == 'lov':  # logical object volume  http://wiki.lustre.org/index.php/Subsystem_Map#lov
                    self.info['lustre.lov_count'] += 1
                elif thr == 'lmv':  # http://wiki.lustre.org/index.php/Subsystem_Map#client_lmv
                    self.info['lustre.lmv_count'] += 1
            fi.close()
        self.devices = devs
        logger.debug("LustreDevices are: %s" % str(devs))
        return True

    def make_descriptors(self, metrics):
        "Make metric descriptors"
        descriptors = {}
        for name, updates in metrics.iteritems():
            descriptor = {
                "name": name,
                "call_back": self.handler,
                "time_max": 90,
                "value_type": "int",
                "units": "",
                "slope": "both",
                "format": "%d",
                "description": "no decription",
                "groups": "lustre",
            }
            descriptor.update(updates)
            descriptors[name] = descriptor
        self.descriptors = descriptors

    @classmethod
    def init(cls, params):
        "Init LustreMetrics class / singleton object"
        obj = cls()
        cls.obj = obj
        obj.set_params(params)
        if not obj.get_lustre_version():
            logger.info('%s: is not a Lustre server or client' % os.uname()[1])
            return []
        metrics = {
            'lustre.version': {
                'value_type': 'string',
                "format": "%s",
                'description': 'Lustre version'
            },
            'lustre.kernel_build': {
                'value_type': 'string',
                "format": "%s",
                'description': 'Kernel build project',
            },
            'lustre.is_mgs': {
                "value_type": "boolean",
                'description': 'Is Lustre MGS server?',
            },
            'lustre.mdt_count': {
                'description': 'Number of MDS running',
            },
            'lustre.ost_count': {
                'description': 'Number of OST running',
            },
        }
        if obj.info.get('lustre.is_mgs', False):
            obj.add_mgs_metrics(metrics)
        if obj.get_lustre_devices():
            obj._add_thr_counts(metrics)
        obj.make_descriptors(metrics)
        return obj.descriptors.values()

    def add_mgs_metrics(self, metrics):
        "Add MGS related metrics into the :dict:`metrics`"
        metrics['lustre.mgs.threads_started'] = {
            'description': 'Lustre: number of MGS threads started',
        }
        metrics['lustre.mgs.threads_max'] = {
            'description': 'Lustre: max number of MGS threads',
        }

    def _add_thr_counts(self, metrics):
        "Add a few counters as metrics based on get_lustre_devices()"
        metrics['lustre.mgc_count'] = {
            'description': 'Lustre: MGC threads (client of MGS)',
        }
        metrics['lustre.mdc_count'] = {
            'description': 'Lustre: MDC threads (client of MDS)',
        }
        metrics['lustre.osc_count'] = {
            'description': 'Lustre: OSC threads (client of OSS)',
        }
        metrics['lustre.lov_count'] = {
            'description': 'Lustre: LOV threads'
        }
        metrics['lustre.lmv_count'] = {
            'description': 'Lustre: LMV threads'
        }
        for dev in self.devices:
            dev.add_metrics(metrics)


def metric_init(params={}):
    ret = []
    try:
        ret = LustreMetrics.init(params)
    except Exception, exc:
        logger.error("metric_init failed: %s" % str(exc))
    return ret


def metric_cleanup():
    "module cleanup callback"
    if not LustreMetrics.obj is None:
        del LustreMetrics.obj
    LustreMetrics.obj = None


if __name__ == '__main__':
    metrics = metric_init()
    #print metrics
    for m in metrics:
        print "%-20s: %s" % (m['name'], m['call_back'](m['name']))
