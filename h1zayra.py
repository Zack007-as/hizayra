import nmap
import socket
import os

def main():
    os.system("clear")
    print ("""

#     # ### #######    .---.  #     # ######     #
#     #  #       #     |---|   #   #  #     #   # #
#     #  #      #      |---|    # #   #     #  #   #
#######  #     #       |---|     #    ######  #     #
#     #  #    #   .---- - ----.  #    #   #   #######
#     #  #   #    :___________:  #    #    #  #     #
#     # ### ######   |  |//|     #    #     # #     #
                     |  |//|
                     |  |//|
                     |  |//|
                     |  |.-|
                     |__|__|
                      \***/
                       \*/
                        V
""")

    n = input('''
[1]-Normal Scan			   [11]-Network Live Hosts scan
[2]-All port Scan	     	   [12]-Vulnerability scan
[3]-Os and Services fingerprinting [13]-Exploit known vulns from the previous option			
[4]-WiFi live hosts discovery	   [14]-Normal scan + output file                          
[5]-Reverse IP lookup
[6]-Traceroute			   
[7]-Slowloris Dos vulnerability check
[8]-WHOIS Lookup
[9]-HeartBleed scan
[10]-IP location tracer
									    											
hizayra~<< ''')


    if n == '1':
         nps()

    if n == '2':
         aps()

    if n == '3':
         osf()

    if n == '4':
         arp()

    if n == '5':
         lookup()

    if n == '6':
         trace1()

    if n == '7':
         DoC()

    if n == '8':
         who()

    if n == '9':
         hbs()

    if n == '10':
         trace()

    if n == '11':
         nsl()

    if n == '12':
         vul()
   
    if n == '13':
         expl()
   
    if n == '14':
          out()
def nps():
    ip = input("Please enter target IP address or host: ")
    print(os.system('nmap --script default ' +ip))
		 
def aps():
    ip = input("Please enter target IP address or host: ")
    print(os.system('nmap -p0-65535 ' +ip))

def osf():
    ip = input("Please enter target IP address or host: ")
    print(os.system('nmap -sV ' +ip))

def arp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    s.close()
    nm = nmap.PortScanner()
    l = nm.scan(hosts = f'{host}/24', arguments = '-sn')
    p = l['scan'].keys()
    p = list(p)
    for i in range(len(p)):
        print("IP",i,p[i])

def lookup():
    ip = input("Enter target IP address or host:")
    print(os.system('curl http://api.hackertarget.com/reverseiplookup/?q=' +ip))

def trace1():
    ip = input("Please enter target IP address:")
    print(os.system('curl https://api.hackertarget.com/mtr/?q=' +ip))

def DoC():
    ip = input("Please enter target IP adress or host:")
    print(os.system('nmap --script http-slowloris-check' +ip))

def who():
    ip = input("Please enter target IP address:")
    print(os.system('nmap -sn --script whois-ip --script-args whois.whodb=nocache -Pn ' +ip))

def hbs():
    ip = input("Please enter target IP adress or host:")
    print(os.system('nmap -p 443 --script ssl-heartbleed ' +ip))

def trace():
    ip = input("Please enter target IP address or host:")
    print(os.system('curl http://api.hackertarget.com/geoip/?q=' +ip))

def nsl():
    ip = input("Please enter target IP address with subnet(ex:192.168.0.0/24):")
    print(os.system('nmap -sn ' +ip))    

def vul():
    ip = input("Please enter target IP address or host:")
    print(os.system('nmap --script vuln -d ' +ip))

def expl():
    os.system("msfconsole")

def out():						
    print("your output file name will be scanput")
    ip = input("Please enter target IP address or host:")
    print(os.system('nmap -oN scanput ' +ip))

if __name__ == "__main__":
    main()
	
