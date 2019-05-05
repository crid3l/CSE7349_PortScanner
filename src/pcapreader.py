from pcapfile import savefile

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

def main():
    print("Hello World")
    myCap = open(basePath + paths[0], 'rb')
    capfile = savefile.load_savefile(myCap, verbose=True)
    print (capfile)
    return

if __name__ == '__main__':
    main()
