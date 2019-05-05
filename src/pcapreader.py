from pcapfile import savefile

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

def main():
    print("Hello World")
    myCap = open(basePath + paths[0], 'rb')
    print(myCap.read())
    # capfile = savefile.load_savefile(myCap, verbose=True)
    # print (capfile)
    # return
    return

if __name__ == '__main__':
    main()
