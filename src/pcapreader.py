from pcapfile import savefile

basePath = "../../../../opt/scans/"
urls = ["connect_scan.pcapng,  multiplescans.pcapng,  scan.pcapng,  tcp_syn_scan.pcapng"]

def main():
    print("Hello World")
    testcap = open(basePath + urls[0], 'rb')
    capfile = savefile.load_savefile(testcap, verbose=True)
    print (capfile)
    return

if __name__ == '__main__':
    main()
