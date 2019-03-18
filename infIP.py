#Imports

import os
import re
import socket
import sys
import httplib
from BeautifulSoup import BeautifulSoup
import datetime
def time():
    now = datetime.datetime.now()
    return str(now)

START = '<title>infIP v 0.1 Report</title><div style="background-color:yellow;text-align:center"><font size="3" color="red"><h1>Report infIP v0.1</h1></font><p><b>Report Generation time<b> </p><b>'+time()+'<b></br></div><font size="3" color="green"><h3><a name="top">Hosts Found</a></h3></font></br>'
END = '</br><div style="background-color:yellow;text-align:center">Author : Debasish Mandal</br>Email : debasishm89@gmail.com</br><b>*****************************************End of Report********************************************</b></div></br></html>'

USER_AGENT = "Mozilla/5.0 (Windows NT 5.1; rv:6.0.1) Gecko/20100101 Firefox/6.0.1"
PRAGMA = "no-cache"
ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
def write1(doc1):
    cont1 = doc1.replace("\n","")
    rep2 = open('Report.html','a')
    rep2.write(cont1)
    rep2.write("</br>")
def write(doc):
    cont = doc.replace("\n","</br>")
    rep1 = open('Report.html','a')
    rep1.write(cont)
def blacklist(dat):
    ip = dat.replace("\n","")
    print "[*] Checking blacklist Database -> ",ip
    type =None
    status = "[*] "
    host = "www.spamhaus.org"
    path = "/query/bl?ip="
    path +=ip
    
    data = ""
    http = httplib.HTTP(host)
    
    http.putrequest("GET", path)
    http.putheader("Host", host)
    http.putheader("User-Agent", USER_AGENT)
    http.putheader("Accept", ACCEPT)   
    http.putheader("Accept-Encoding", "gzip, deflate")
    http.putheader("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
    http.putheader("Connection", "keep-alive")  
    http.putheader("","\n")
    http.putheader("","\n")
    http.endheaders()
    
    http.send(data)

    
    errcode, errmsg, headers = http.getreply()
    
    f = http.getfile()
    html = f.read()
    
    soup = BeautifulSoup(html)
    tag = soup.findAll('b')
    for item in tag:
        if item.text != "Not Listed":
            if item.text != "Listed.":
                status += item.text
                status += "\n"
                status += "[*] "
    print status
    write('<font size="2" color="blue"><h3>Black List Lookup Result</h3></font>');
    write(status);
                
def rev(ip):
    print "[*] Trying to resolve hostname -> ",ip
    try:
        dns = socket.gethostbyaddr(ip)
        print dns[0]
        return dns[0]
    except:
        return "Could not resolve host name"
        print "[*] Could not resolve host name"

def whois(ipd):
    #test = "69.171.229.14"
    name = ipd.replace("\n","")
    print "[*] Checking whois database for information -> ",ip
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect(("whois.arin.net", 43))
    s1.send(name + "\r\n")
    response = ''
    while True:
        d = s1.recv(4096)
        response += d
        if d == '':
            break
    s1.close()
    #return response[248:-123]
    response = response.replace("#", "[*]");
    print response
    write('<font size="2" color="blue"><h3>WHOIS Lookup Result</h3></font>');
    write(response);


print "#######################################################"
print "#                   Welcome                           #"
print "Domain Registration Information will be according to  #"
print "the whois.arin.net database                           #"
print "Blacklisting information will be according to         #"
print "            http://www.spamhaus.org/                  #"
print "XBL = The Spamhaus Exploits Block List (XBL) is a     #" 
print "realtime database of IP addressesof hijacked PCs      #" 
print "infected by illegal 3rd party exploits, including     #"
print "open proxies (HTTP,socks, AnalogX, wingate, etc),     #"
print "worms,viruses with built-in spam engines, and other   #"
print "types of trojan-horse exploits.                       #"
print "SBL = The Spamhaus Block List (SBL) Advisory is a     #"
print "database of IP addresses from which Spamhaus does not #"
print "recommend the acceptance of electronic mail.          #"
print "PBL = The Spamhaus PBL is a DNSBL database of end-user#" 
print "IP address ranges which should not be delivering unaut#"
print "henticated SMTP email to any Internet mail server exce#"
print "pt those provided for specifically by an ISP for that #"
print "customer's use.                                       #"
print "#          Author : Debasish Mandal                   #"
print "#         Email : debasishm89@gmail.com               #"
print "#    Facebook Page : facebook.com/raza.whitehat       #"
print "#######################################################"



rep = open('Report.html','w')
rep.write(START)
rep.close()


#Wait for the user to trigger the scan....
d = raw_input("[*] Press Enter to start...")
print "[*] Starting @",time()
cmd = r"netstat -a -n"
cmd = os.popen(cmd)
clr = open('temp.db','w')
clr.write("")
clr.close()
temp = ''
f1 = open('temp.db','a')
print "[*] Getting the List of IPs form Netstat"
for line in cmd.readlines():
    ip1 = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
    size = len(ip1)
    if size > 1:
         ip = ip1[1]
         if ip != "0.0.0.0":  
             if ip != "127.0.0.1":  
                 if ip[0:3] != "192": 
                     if ip[0:3] != "10.":
                         if ip[0:3] != "172":
                             if ip not in temp:
                                 f1.write(ip)
                                 f1.write("\n")
                                 temp += ip
                                 #temp += "\n"
                             
f1.close()

# List IP addresses found.
st1 = '<a href="#'
#IP
st2 = '">'
#IP
st3 = '</a>'
nd = ''
print "[*] Active Hosts found \n"
read = open('temp.db','r')
hosts = read.readlines()
for single in hosts:
    print single
    main = str(st1)+str(single)+str(st2)+str(single)+str(st3)
    write1(main);
write('<font size="3" color="green"><h3>Host Details</h3></font>');
print "[*] Starting Operation"
read.close()
#Start Operation
empty = open('temp.db','r')
if empty.read() == "":
    print "[*] No host found to test"
    write("No host found   !!  Make sure you are connected to the Internet  !!");
empty.close()

var1 = '</br><div style="background-color:yellow;text-align:center"><font color="black"><u><b>HOST : '
var2 = '</b></u></font></div>'



v1 = '<a name="'
#IP
v2 = '">'
#Details
v3 = '</a>'
b2t = '<a href="#top">Back to Top</a>'
details = ''
f2 = open('temp.db','r')
line = f2.readlines()
for ip in line:
    print "#######################################################"
    print "##         Operating on ip",ip
    print "#######################################################"
    details += var1
    tempip = ip.replace("\n","")
    details += v1   
    details += tempip  
    details += v2    
    details += tempip  
    details += ' ( '
    details += rev(ip)
    details += ' )</br>'
    details += v3   #Add </a>
    details += var2
    details += b2t
    write(details);
    rev(ip);
    whois(str(ip));
    blacklist(str(ip));
    details = ''
write(END);
print "[*] Opening Report"
os.startfile("Report.html")
print "[*] Done"
print "[*] Exit"
f2.close()
