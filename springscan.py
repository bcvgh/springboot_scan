import json
import queue

import requests
import re
import time
from optparse import OptionParser
import threading
requests.packages.urllib3.disable_warnings()
headers = {
             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
             "Accept":"*/*",
             "Accept-Encoding":"gzip,deflate",
             "Connection":"close",
             "Content-Type":"application/json"
             }


def file_write(output, res):
    with open(output, 'w') as f:
        if res:
            for r in res:
                f.write(r+'\n')
        # if res:
        #     f.writelines(res)


def file_read(file):
    with open(file, 'r') as f:
        res = f.readlines()
    return res


def request_(url, method, api, type='text'):
    if method == 'get':
        res = requests.get(url + '/'+api, headers=headers, verify=False)
        if res.status_code == 200 or res.status_code == 400:
            if type == 'json':
                return res.json()
            return res.text
        res = requests.get(url + '/actuator/'+api, headers=headers, verify=False)
        if res.status_code == 200 or res.status_code == 400:
            if 'json' in type:
                return res.json()
            return res.text
    if method == 'post':
        res = requests.post(url + '/'+api, headers=headers, verify=False)
        if res.status_code == 200 or res.status_code == 400:
            if 'json' in type:
                return res.json()
            return res.text
        res = requests.post(url + '/actuator/'+api, headers=headers, verify=False)
        if res.status_code == 200 or res.status_code == 400:
            if type == 'json':
                return res.json()
            return res.text
    return 0

# class My_Thread(threading.Thread):
#     def __init__(self, method, url):
#         super().__init__()
#         self.method = method
#         self.url = url
#
#     def run(self):
#         if self.method == 'url_scan':
#             Main.url_scan(self)
#         if self.method == 'file_scan':
#             Main.file_scan(self)

class BaseScan(object):

    # res = []

    def __init__(self, url):
        self.url = url

    def get_env(self, *type):
        return request_(self.url, 'get', 'env', type)

    def post_env(self):
        return request_(self.url, 'post', 'env')

    def get_refresh(self):
        return request_(self.url, 'get', 'refresh')

    def get_jolokia(self):
        return request_(self.url, 'get', 'jolokia')

    def post_restart(self):
        return request_(self.url, 'post', 'restart')

    def get_jolokialist(self):
        return request_(self.url, 'get', 'jolokia/list')

    def rely_version(self, dependency1, version=0):
        pattern1 = re.compile(
            r'({0}\\\\\d\.\d\.\d\.RELEASE)|({0}-\d\.\d\.\d\.RELEASE\.jar)'.format(dependency1))
        pattern2 = re.compile(r'\d\.\d\.\d')
        res = self.get_env()
        if res:
            if dependency1 in res:
                dependency1_version = pattern1.search(res)
                dependency1_version = pattern2.search(dependency1_version.group())
                dependency1_version = int(dependency1_version.group().replace(".", ""))
                if dependency1_version <= version:
                    if self.get_refresh() and self.post_env():
                        return 1
        else:
            return 0

    def m_thread(self, num, method):
        for value in range(1,num):
            t=threading.Thread(target=method,)

class My_Thread(threading.Thread):
    def __init__(self, method, url):
        super().__init__()
        self.method = method
        self.url = url

    def run(self):
        if self.method == 'url_scan':
            Main.url_scan()
        if self.method == 'file_scan':
            Main.file_scan()

class Spring(BaseScan):
    # def __init__(self,url):
    #     self.url=url

    def spring_spel(self):
        pass

    def sping_snakeyaml(self):
        vul = "spring cloud SnakeYAML RCE"
        dependency1 = "spring-boot-starter"
        vul_version = 130
        vul_exist = self.rely_version(dependency1, vul_version)
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_xstream(self):
        vul = "eureka xstream deserialization RCE"
        dependency1 = "eureka-client"
        vul_version = 187
        vul_exist = self.rely_version(dependency1, vul_version)
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_jolokia_logback(self):
        vul_exist=0
        vul = "jolokia logback JNDI RCE"
        dependency1 = "reloadByURL"
        dependency2 = "ch.qos.logback.classic.jmx.JMXConfigurator"
        res = self.get_jolokialist()
        try:
            if dependency1 in res and dependency2 in res:
                vul_exist = 1
        except TypeError:
                pass
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_jolokia_realm(self):
        vul_exist = 0
        vul = "jolokia Realm JNDI RCE"
        dependency1 = "type=MBeanFactory"
        dependency2 = "createJNDIRealm"
        res = self.get_jolokialist()
        try:
            if dependency1 in res and dependency2 in res:
                vul_exist = 1
        except TypeError:
            pass
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_h2query(self):
        vul_exist = 0
        vul = "restart h2 database query RCE"
        dependency1 = "h2database"
        res = self.get_env()
        try:
            if dependency1 in res:
                if self.post_env() and self.post_restart():
                    vul_exist = 1
        except TypeError:
            pass
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_h2console(self):
        vul_exist = 0
        vul = "h2 database console JNDI RCE"
        dependency1 = "spring.h2.console.enabled"
        res = self.get_env('json')
        try:
            if res['propertySources'][5]['properties']['spring.h2.console.enabled']['value'] or dependency1 in res:
                if self.post_env() and self.post_restart():
                    vul_exist = 1
        except BaseException:
            pass
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_mysql(self):
        vul_exist = 0
        vul = "mysql jdbc deserialization RCE"
        dependency1 = "mysql-connector-java"
        res = self.get_env()
        try:
            if dependency1 in res:
                if self.post_env() and self.post_restart():
                    vul_exist = 1
        except TypeError:
            pass
        if vul_exist:
            out_print = "{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_logging_logback(self):
        vul_exist = 0
        vul = "restart logging.config logback JNDI RCE"
        if self.post_env() and self.post_restart():
            vul_exist = 1
        if vul_exist:
            out_print = "{0}可能存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_logging_groovy(self):
        vul_exist = 0
        vul = "restart logging.config groovy RCE"
        if self.post_env() and self.post_restart():
            vul_exist = 1
        if vul_exist:
            out_print = "{0}可能存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_main_groovy(self):
        vul_exist = 0
        vul = "restart spring.main.sources groovy RCE"
        if self.post_env() and self.post_restart():
            vul_exist = 1
        if vul_exist:
            out_print = "{0}可能存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))

    def spring_datasource_h2(self):
        vul_exist = 0
        vul = "restart spring.datasource.data h2 database RCE"
        dependency1 = "h2database"
        dependency2 = "spring-boot-starter-data-jpa"
        res = self.get_env()
        try:
            if dependency1 in res and dependency2 in res:
                if self.post_env() and self.post_restart():
                    vul_exist = 1
        except TypeError:
            pass
        if vul_exist:
            out_print="{0}存在{1}漏洞".format(self.url, vul)
            print(out_print)
            time.sleep(10)
            return out_print
        else:
            print("{0}不存在{1}漏洞".format(self.url, vul))


class Main(object):
    res = []

    def __init__(self):
        parser = OptionParser()
        parser.add_option("-f", "--file", help="read url from file")
        parser.add_option("-u", "--url", help="target url")
        parser.add_option("-o", "--output", help="results output file")
        parser.add_option("-t", "--thread", help="thread number")
        (options, args) = parser.parse_args()
        self.url = options.url
        self.file = options.file
        self.output = options.output
        if options.thread:
            self.thread = int(options.thread)
        else:
            self.thread = 5

        if self.url:
            self.url_scan()
        elif self.file:
            self.file_scan()

    def spring_scan(self):
        # res = []
        spring = Spring(self.url)
        n = spring.sping_snakeyaml()
        if n:
            self.res.append(n)
        n = spring.spring_xstream()
        if n:
            self.res.append(n)
        n = spring.spring_jolokia_logback()
        if n:
            self.res.append(n)
        n = spring.spring_jolokia_realm()
        if n:
            self.res.append(n)
        n = spring.spring_h2query()
        if n:
            self.res.append(n)
        n = spring.spring_h2console()
        if n:
            self.res.append(n)
        n = spring.spring_mysql()
        if n:
            self.res.append(n)
        n = spring.spring_logging_groovy()
        if n:
            self.res.append(n)
        n = spring.spring_logging_logback()
        if n:
            self.res.append(n)
        n = spring.spring_main_groovy()
        if n:
            self.res.append(n)
        n = spring.spring_datasource_h2()
        if n:
            self.res.append(n)
        del spring
        # return self.res

    def log4j2_scan(self):
        pass

    def url_scan(self, q=0, file_url=False):
        # res = self.spring_scan()
        if file_url:
            self.url = q.get()
        self.spring_scan()
        if self.output:
            file_write(self.output, self.res)
        else:
            return False

    def file_scan(self):
        res = file_read(self.file)
        q = queue.Queue()
        thread_num = []
        for line in res:
            line = line.strip()
            q.put(line)
        while q.qsize() != 0:
            for i in range(0, self.thread):
                t = threading.Thread(target=self.url_scan, args=(q, True,))
                t.start()

        # for i in range(0,10):
        #     t = threading.Thread(target=self.url,args=(q, True,))
        # for i in range(0, 2):
        #     t = threading.Thread(target=self.url_scan, args=(q, True,))
        #     t.start()
        #     t.join()
        #     thread_num.append(t)
        # for t in thread_num:

        # self.url = line.strip()
        # self.url_scan()





if __name__ == "__main__":
    i = Main()
    # spring = Spring("http://121.36.76.19:7000")
    # spring.sping_snakeyaml()
    # spring.spring_xstream()
    # spring.spring_jolokia_logback()
    # spring.spring_jolokia_realm()
    # spring.spring_h2query()
    # spring.spring_h2console()
    # spring.spring_mysql()
    # spring.spring_logging_groovy()
    # spring.spring_logging_logback()
    # spring.spring_main_groovy()
    # spring.spring_datasource_h2()
