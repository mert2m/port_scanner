from __future__ import print_function
import optparse
from socket import *
from threading import *

kilitekrani = Semaphore(value=1)  # Create a semaphore

def connectScan(targetHost, targetPort):
    try:
        connectSocket = socket(AF_INET, SOCK_STREAM)  # Create a socket
        connectSocket.connect((targetHost, targetPort))  # Establish connection
        connectSocket.send(b"")  # Send an empty data
        results = connectSocket.recv(100)  # Receive data
        kilitekrani.acquire()  # Acquire the lock
        print("[+] %d/tcp opened" % targetPort)
        print("[+] " + str(results))
    except Exception as e:
        kilitekrani.acquire()
        print("[-] %d/tcp closed" % targetPort)
    finally:
        kilitekrani.release()
        connectSocket.close()

def portScan(targetHost, targetPorts):
    try:
        targetIp = gethostbyname(targetHost)  # Resolve host to IP
    except:
        print("[-] Cannot resolve '%s': Unknown host" % targetHost)
        return

    try:
        targetName = gethostbyaddr(targetIp)  # Get hostname from IP
        print("\n[+] Search results for: " + targetName[0])
    except:
        print("\n[+] Search results for: " + targetIp)
        setdefaulttimeout(1)

    for port in targetPorts:  # Scan through ports
        t = Thread(target=connectScan, args=(targetHost, int(port)))
        t.start()

def main():
    parser = optparse.OptionParser("usage %prog -H <target host> -p <target port>")
    parser.add_option("-H", dest="targetHost", type="string", help="specify target host")
    parser.add_option(
        "-p",
        dest="targetPorts",
        type="string",
        help="specify target ports separated by commas",
    )
    (options, args) = parser.parse_args()

    targetHost = options.targetHost
    targetPorts = str(options.targetPorts).split(",")

    if (targetHost is None) or (targetPorts[0] is None):
        print(parser.usage)
        exit(0)

    portScan(targetHost, targetPorts)


if __name__ == "__main__":
    main()
