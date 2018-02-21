# linux-python-ntx
Scripts for reporting on Nutanix (Linux python)

## setup Nutanix API Credentials with encryption
ntx_creds.py

`
$ python ntx_creds.py -h
usage: ntx_creds.py [-h] [-f FILENAME] [-i IPADDR] [-u USERNAME]
                    [-s SYSTEMNAME] [-D] [-w] [-W] [-U SUUID] [-r] [-R]

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        Config file to read (default: ntx_info.conf)
  -i IPADDR, --ipaddr IPADDR
                        IP Address (default: )
  -u USERNAME, --username USERNAME
                        Username (default: )
  -s SYSTEMNAME, --systemname SYSTEMNAME
                        System name (default: )
  -D, --debug           Print debug (default: False)
  -w, --write           Write Authentication data to config file (default:
                        False)
  -W, --writeuuid       Write UUID data to config file (default: False)
  -U SUUID, --suuid SUUID
                        System UUID (default: )
  -r, --read            Read and Print Authentication data to config file
                        (default: False)
  -R, --decread
`
