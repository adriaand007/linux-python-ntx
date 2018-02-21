#!/usr/bin/python
import ConfigParser
from datetime import datetime
from optparse import OptionParser
import requests

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename", default="ntx_rpt.conf",
                  help="Config file to read [default: %default]")
(options, args) = parser.parse_args()

Config = ConfigParser.ConfigParser()
Config.read(options.filename)

hostsv = {}
hostsm = {}
vmddv = {}
hstddv = {}
hstmmv = {}
hstccv = {}
clddv = {}
clmmv = {}
clccv = {}
clccvv = {}
clcntv = {}
clvmcv = {}
HostDetail = {}

def main(ipe):
    requests.packages.urllib3.disable_warnings()
    base_url = "https://" + ipe + ":9440/api/nutanix/v2.0/"
    #base_url = "https://" + ipe + ":9440/PrismGateway/services/rest/v1/"
    reqs = requests.Session()
    reqs.auth = (susername, spassword)
    reqs.headers.update({'Content-Type': 'application/json; charset=utf-8'})
    file3 = open('ntx-rpt-' + clusterip + '.csv', 'w')
    data = reqs.get(base_url + 'vms/', verify=False).json()
    dcluster1 = reqs.get(base_url + 'hosts/', verify=False).json()
    dcluster2 = reqs.get(base_url + 'cluster/', verify=False).json()
    vmdiskdata = reqs.get(base_url + 'virtual_disks/', verify=False).json()
    clname = str(dcluster2['name'])
    clcntv[clname] = dcluster2["num_nodes"]

    for fordd in vmdiskdata["entities"]:

        try:
            vmddv[fordd["attached_vmname"].replace(" ", "-")] = vmddv[fordd["attached_vmname"].replace(" ", "-")] + fordd["disk_capacity_in_bytes"]
        except:
            try:
                vmddv[fordd["attached_vmname"].replace(" ", "-")] = fordd["disk_capacity_in_bytes"]
            except:
                vmddv["none"] = fordd["disk_capacity_in_bytes"]

    for forf in dcluster1["entities"]:
        hostsv[forf["uuid"]] = forf["name"]

    for fort in dcluster1["entities"]:
        hostsm[fort["name"]] = fort["block_model_name"]

    for hst in dcluster1["entities"]:
        HostDetail[hst["name"]] = len(hst["disk_hardware_configs"]), hst["num_cpu_cores"], hst["num_cpu_sockets"], (hst["memory_capacity_in_bytes"]/1024/1024/1024), hst["num_vms"], (long(hst["usage_stats"]["storage.capacity_bytes"])/1024/1024/1024), (long(hst["usage_stats"]["storage.usage_bytes"])/1024/1024/1024), (long(hst["usage_stats"]["storage.logical_usage_bytes"])/1024/1024/1024), (long(hst["usage_stats"]["storage.free_bytes"])/1024/1024/1024), clname
        try:
            clvmcv[clname] = clvmcv[clname] + hst["num_vms"]
        except:
            clvmcv[clname] = hst["num_vms"]

    for fore in data["entities"]:

        try:
            namev = str(fore["name"].replace(" ", "-"))
        except:
            namev = "name_error"

        try:
            vmdisks = vmddv[namev]/1024/1024/1024
        except:
            vmdisks = "error"

        try:
            uuidv = fore["uuid"]
        except:
            uuidv = "uuidv_error"

        try:
            vmip = reqs.get(base_url + "vms/" + uuidv + '/nics/', verify=False).json()
            for k in vmip["entities"]:
                vmipv = k["requested_ip_address"]
        except:
            vmipv = "vmip_error"

        try:
            hostnamev = str(hostsv[fore["host_uuid"]])
        except:
            hostnamev = "hst_err"

        try:
            memmbv = str(fore["memory_mb"])
        except:
            memmbv = "memory_mb_error"

        try:
            cpuv = str(fore["num_vcpus"])
        except:
            cpuv = "num_vcpus_error"

        try:
            powersv = fore["power_state"]
        except:
            powersv = "power_state_error"

        file3wr = namev + "," + vmipv + "," + uuidv + "," + hostnamev + "," + memmbv + "," + cpuv + "," + powersv + "," + clname + "," + dttmval + "," + str(vmdisks)
        #print file3wr
        try:
            hstddv[hostnamev] = hstddv[hostnamev] + vmdisks
        except:
            hstddv[hostnamev] = vmdisks

        try:
            hstmmv[hostnamev] = hstmmv[hostnamev] + int(memmbv)/1024
        except:
            hstmmv[hostnamev] = int(memmbv)/1024

        try:
            hstccv[hostnamev] = hstccv[hostnamev] + int(cpuv)
        except:
            hstccv[hostnamev] = int(cpuv)

        file3.write(file3wr + "\n")
    for forvv in hstddv:
        try:
            clddv[clname] = clddv[clname] + hstddv[forvv]
        except:
            clddv[clname] = hstddv[forvv]
        try:
            clmmv[clname] = clmmv[clname] + hstmmv[forvv]
        except:
            clmmv[clname] = hstmmv[forvv]
        try:
            clccv[clname] = clccv[clname] + hstccv[forvv]
        except:
            clccv[clname] = hstccv[forvv]
        try:
            clccvv[clname] = clccvv[clname] + HostDetail[forvv][1]
        except:
            if forvv != "hst_err":
                clccvv[clname] = HostDetail[forvv][1]
            else:
                pass

if __name__ == "__main__":

    sections = Config.sections()
    dttmval = datetime.now().strftime('%Y-%m-%d:%H:%M:%S')

    for clustern in sections:
        if "Cluster" in clustern:
            #print(clustern)
            clusterip = Config.get(clustern, 'ip')
            susername = Config.get(clustern, 'name')
            spassword = Config.get(clustern, 'value')
            main(clusterip)
        else:
            notcluster = 1

    print "cluster".ljust(14), "hostname".rjust(10), "blckmdl".rjust(12), "dsksgnd".rjust(15), "memsgnd".rjust(7), "cpusgnd".rjust(7), "memcpurt".rjust(7), "dcnt".rjust(4), "cpucnt".rjust(4), "sktcnt".rjust(4), "ttlmem".rjust(5), "vmcnt".rjust(4), "cptbtsg".rjust(7), "usbtsg".rjust(7), "lusbtsg".rjust(7), "frbtsg".rjust(7), "vcpurt".rjust(6)
    for vv in hstddv:
        if vv == "hst_err":
            pass
        else:
            try:
                print HostDetail[vv][9].ljust(14), vv.rjust(10), hostsm[vv].rjust(12), str(hstddv[vv]).rjust(15), str(hstmmv[vv]).rjust(7), str(hstccv[vv]).rjust(7), "{:.2f}".format(round(float(hstmmv[vv])/float(hstccv[vv]), 2)).rjust(8), str(HostDetail[vv][0]).rjust(4), str(HostDetail[vv][1]).rjust(6), str(HostDetail[vv][2]).rjust(6), str(HostDetail[vv][3]).rjust(6), str(HostDetail[vv][4]).rjust(5), str(HostDetail[vv][5]).rjust(7), str(HostDetail[vv][6]).rjust(7), str(HostDetail[vv][7]).rjust(7), str(HostDetail[vv][8]).rjust(7), "{:.2f}".format(round(float(hstccv[vv])/float(HostDetail[vv][1]), 2)).rjust(6)
            except:
                print vv, str(hstddv[vv]).rjust(15), str(hstmmv[vv]).rjust(7), str(hstccv[vv]).rjust(7), str(round(float(hstmmv[vv])/float(hstccv[vv]), 2)).rjust(7)


    print "cluster".ljust(14), "clhcnt".rjust(5), "dsksgnd".rjust(10), "memsgnd".rjust(8), "cpusgnd".rjust(8), "memcpurt".rjust(8), "vcpurt".rjust(7), "vmcnt".rjust(5), "vmphst".rjust(7)
    for cv in clddv:
        print cv.ljust(14), str(clcntv[cv]).rjust(6), str(clddv[cv]).rjust(10), str(clmmv[cv]).rjust(8), str(clccv[cv]).rjust(8), "{:.2f}".format(round(float(clmmv[cv])/float(clccv[cv]), 2)).rjust(8), "{:.2f}".format(float(clccv[cv])/float(clccvv[cv])).rjust(7), str(clvmcv[cv]).rjust(5), "{:.2f}".format(round(float(clvmcv[cv])/float(clcntv[cv]), 2)).rjust(7)
