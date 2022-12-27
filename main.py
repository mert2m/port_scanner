from __future__ import print_function
import optparse
from socket import *
from threading import *

kilitekrani = Semaphore(value = 1) #


def baglanTara(hdfHost, hdfPort):
    try:
        baglanSoket = socket(AF_INET, SOCK_STREAM) #soket açma fonksiyonu
        baglanSoket.connect(hdfHost, hdfPort)
        baglanSoket.send("")
        results = baglanSoket.recv(100)
        kilitekrani.acquire() #acquire çağrısı
        print("[+] %d/tcp açıldı" % hdfPort)
        print("[+] "+str(results))
    except:
        kilitekrani.acquire()
        print("[-] %d/tcp kapandı" % hdfPort)
    finally:
        kilitekrani.release()
        baglanSoket.close()
def portTara(hdfHost, hdfPort):
    try:
        hdfIp = gethostbyname(hdfHost) #host adından ip edinme
    except:
        print("[-] Çözümlenemedi '%s': Bilinmeyen host" %hdfHost)
        return
    try:
        hdfAd = gethostbyaddr(hdfIp) # ipden host adını öğrenme
        print("\n[+] Arama sonuçları için: "+ hdfAd[0])
    except:
        print("\n[+] Arama sonuçları için: " + hdfIp)
        setdefaulttimeout(1)
    for hdfHost in hdfPort: #döngü içinde hostları ve portları arama
        t = Thread(target = baglanTara, args=(hdfHost, int(hdfPort)))
        t.start()

def main():
    parser = optparse.OptionParser("usage %prog -H" + " <hedeflenen host> -p <hedeflenen port>")
    parser.add_option("-H", dest="hdfHost", type="string", help="specify hedef host")
    parser.add_option(
        "-p",
        dest="hdfPort",
        type="string",
        help="virgülle ayrılmış hedef bağlantı noktalarını belirtin",
    )
    (options, args) = parser.parse_args()
    hdfHost = options.hdfHost
    hdfPort = str(options.hdfPort).split(",")
    if (hdfHost == None) | (hdfPort[0] == None):
        print(parser.usage)
        exit(0)
    portTara(hdfHost, hdfPort)


if __name__ == "__main__":
    main()