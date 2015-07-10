import dpkt
import socket
import matplotlib.pyplot as plt
import matplotlib.mlab as mlab
import numpy as np
from scipy.stats import norm
import sys
import re

# Declaration of variables

path = ""
fil = ""

# Measure packets, requests and responses
countall = 0        # Count total amount of packets processed
countudp = 0        # Count amount of udp packets processed
countdns = 0        # Count amount of dns packets processed
reqerror1 = 0        # Count number of errors in requests
reserror1 = 0        # Count number of errors in response
nnerr1 = 0          # Count number of non no error responses
reqerror2 = 0        # Count number of errors in requests
reserror2 = 0        # Count number of errors in response
nnerr2 = 0          # Count number of non no error responses
reqerror3 = 0        # Count number of errors in requests
reserror3 = 0        # Count number of errors in response
nnerr3 = 0          # Count number of non no error responses
nonreqres = 0        # Count number of non requests and responses
adflag1 = 0          # Count number of AD flag packets in case of DNSSEC
adflag2 = 0          # Count number of AD flag packets in case of DNSSEC
adflag3 = 0          # Count number of AD flag packets in case of DNSSEC


# Declaration of dictionaries

store1 = dict()         # Store Unbound data
store2 = dict()         # Store BIND data
store3 = dict()         # Store PowerDNS data
trace = dict()          # Store general data

# Declaration of lists

# Stores the size of udp datagrams
packsize1 = []      # The size of UDP datagrams of Store 1
packsize2 = []      # The size of UDP datagrams of Store 2
packsize3 = []      # The size of UDP datagrams of Store 3
typelist = []       # Collects the type of dns queries
opcodelist1 = []     # Collects the opcodes of dns replies for Store 1
opcodelist2 = []     # Collects the opcodes of dns replies for Store 2
opcodelist3 = []     # Collects the opcodes of dns replies for Store 3
rcodelist1 = []     # Collects the rcode of dns replies for Store 1
rcodelist2 = []     # Collects the rcode of dns replies for Store 2
rcodelist3 = []     # Collects the rcode of dns replies for Store 3
noerrorlist1 = []   # Collects times of specific rcodes for Store 1
servlist1 = []      # Collects times of specific rcodes for Store 1
nxlist1 = []        # Collects times of specific rcodes for Store 1
noerrorlist2 = []   # Collects times of specific rcodes for Store 2
servlist2 = []      # Collects times of specific rcodes for Store 2
nxlist2 = []        # Collects times of specific rcodes for Store 2
noerrorlist3 = []   # Collects times of specific rcodes for Store 3
servlist3 = []      # Collects times of specific rcodes for Store 3
nxlist3 = []        # Collects times of specific rcodes for Store 3
adlist1 = []        # Collects times of DNSSEC data for Store 1
adlist2 = []        # Collects times of DNSSEC data for Store 2


def readfile(arguments):
    global path, fil

    if len(arguments) == 3:
        fil = str(arguments[2])
        path = str(arguments[1])
        fleraw = path + fil + ".pcap"
        fl = open(fleraw)

    else:
        sys.exit("Too many system arguments")

    return fl


def writetotextfile(linetowrite):           # For writing purposes
    global path, fil

    ftxt = open(path + fil + ".txt", 'a')
    ftxt.write(linetowrite + "\n")
    ftxt.close()


def ethdata(buf):                       # Extract ethernet frame from pcap
    eth = dpkt.ethernet.Ethernet(buf)
    return eth


def ipdata(eth):                        # Extract ip packet from ethernet frame
    ip = eth.data
    return ip


def udpdata(ip):                        # Extract udp datagram from ip packet
    udp = ip.data
    return udp


def dnsdata(udp):                       # Extract dns data from udp datagram
    dns = dpkt.dns.DNS(udp.data)
    return dns


def dnsaddata(pcktf):     # Check whether response has authentic data flag on for DNSSEC DPKT does not parse AD flag
    flags = ""                               # Used to store the flags data
    udpheader = pcktf[34:42]                # udp header to extract length of dns packet
    udplen = udpheader[4:6]                 # The length is 16-bit in length
    bodylen = ord(udplen[0])*256+ord(udplen[1])-8   # Retrieve the actual length minus the length ofo the checksum
    dnsbody = pckt[42:(42+bodylen)]                 # Retrieve DNS data by using the length
    x = dnsbody[2:4]                                # Retrieve the flags in DNS
    for byt in x:
        bit = bin(ord(byt))[2:].zfill(8)            # Conversion to binary
        flags += bit                                # Concatenate the two bytes that represent the flags

    return flags[10]                                # AD flag is the eleventh position


def storestats(store, storeid):      # Stats abouts records in store
    cntreq = 0      # Counter for entries with only a request
    cntres = 0      # Counter for entries with a request and response
    strange = 0     # Counter for strange cases where an unusual number of records are present

    lenstore = len(store)

    for i in store:
        if len(store[i]) == 3:
            cntres += 1

        elif len(store[i]) == 1:
            cntreq += 1

        else:
            strange += 1

    print "--------------------------------------------------------------------------"
    print "Individual store statistics"
    print "Store %d contains %d records" % (storeid, lenstore)
    print "This store contains %d records with only requests" % cntreq
    print "This store contains %d records with both requests and responses" % cntres
    print "This store contains %d records with strange cases" % strange
    print "--------------------------------------------------------------------------"


def namestorestats(tracef):         # Figure out how many times domain names occur

    longf = dict()           # occurrences per unique name

    for item in tracef:
        length = (len(tracef[item]) / 3)
        if length not in longf:
            longf[length] = [item]

        else:
            longf[length].append(item)

    maxocc = max(longf.keys())
    maxdom = len(longf[maxocc])
    minocc = min(longf.keys())
    mindom = len(longf[minocc])
    longlist = np.array(longf.keys())
    avocc = np.mean(longlist)
    stdocc = np.std(longlist)

    print "--------------------------------------------------------------------------"
    print "How many times do domain names occur"
    print "The max amount of similar name occurences: %d" % maxocc
    print "The number of names in max occurences: %d" % maxdom
    print "The min amount of occurences: %d" % minocc
    print "The number of names in min occurences: %d" % mindom
    print "The average and std.: {0} and {1}".format(avocc, stdocc)
    print "--------------------------------------------------------------------------"


def typestorestats(typelistf):       # Stats about RR type

    atype = 0
    aaaatype = 0
    ptrtype = 0
    nstype = 0
    cnametype = 0
    dnametype = 0
    soatype = 0
    mxtype = 0
    txttype = 0
    srvtype = 0
    elsetype = 0

    for dnstype in typelistf:
        if dnstype == 1:     # A records
            atype += 1

        elif dnstype == 28:  # AAAA record
            aaaatype += 1

        elif dnstype == 12:  # PTR record
            ptrtype += 1

        elif dnstype == 2:   # NS record
            nstype += 1

        elif dnstype == 5:   # CNAME record
            cnametype += 1

        elif dnstype == 39:  # DNAME record
            dnametype += 1

        elif dnstype == 6:   # SOA record
            soatype += 1

        elif dnstype == 15:  # MX record
            mxtype += 1

        elif dnstype == 16:  # TXT record
            txttype += 1

        elif dnstype == 33:  # SRV record
            srvtype += 1

        else:                # All other records
            elsetype += 1

    print "--------------------------------------------------------------------------"
    print "RR Type general statistics"
    print "Type A: %d" % atype
    print "Type AAAA: %d" % aaaatype
    print "Type PTR: %d" % ptrtype
    print "Type NS: %d" % nstype
    print "Type CNAME: %d" % cnametype
    print "Type DNAME: %d" % dnametype
    print "Type SOA: %d" % soatype
    print "Type MX: %d" % mxtype
    print "Type TXT: %d" % txttype
    print "Type SRV: %d" % srvtype
    print "Type others: %d" % elsetype
    print "--------------------------------------------------------------------------"


def flagstorestats(opcodelistf, rcodelistf, storeid):        # Stats about the flags in DNS

    # Opcode
    queryopcode = 0
    elseopcode = 0

    # Rcode
    noerrorrcode = 0
    formerrrcode = 0
    servfailrcode = 0
    nxdomainrcode = 0
    notimprcode = 0
    refusedrcode = 0
    elsercode = 0

    for opcode in opcodelistf:
        if opcode == 0:
            queryopcode += 1

        else:
            elseopcode += 1

    for rcode in rcodelistf:
        if rcode == 0:
            noerrorrcode += 1

        elif rcode == 1:
            formerrrcode += 1

        elif rcode == 2:
            servfailrcode += 1

        elif rcode == 3:
            nxdomainrcode += 1

        elif rcode == 4:
            notimprcode += 1

        elif rcode == 5:
            refusedrcode += 1

        else:
            elsercode += 1

    print "--------------------------------------------------------------------------"
    print "Opcode and Rcode general statistics for Store: %d" % storeid
    print "Opcode query: %d" % queryopcode
    print "Opcode others: %d" % elseopcode
    print "Rcode no error: %d" % noerrorrcode
    print "Rcode format error: %d" % formerrrcode
    print "Rcode serv fail: %d" % servfailrcode
    print "Rcode nx domain: %d" % nxdomainrcode
    print "Rcode not implemented: %d" % notimprcode
    print "Rcode refused: %d" % refusedrcode
    print "Rcode others: %d" % elsercode
    print "--------------------------------------------------------------------------"


def numberofstats(countallf, countudpf, nonreqresf, tracef, reqerror1f, reserror1f,
                  reqerror2f, reserror2f, reqerror3f=0, reserror3f=0):

    print "----------------------------------------------------------------------------"
    print "Overall statistics about data:"
    print "Number of packets processed: %d" % countallf
    print "Number of udp packets processed: %d" % countudpf
    print "Number of dns packets that are neither requests nor responses: %d" % nonreqresf
    print "Number of dns names that are distinct: %d" % (len(tracef))
    print "Number of request errors in Store 1: %d" % reqerror1f
    print "Number of response errors in Store 1: %d" % reserror1f
    print "Number of request errors in Store 2: %d" % reqerror2f
    print "Number of response errors in Store 2: %d" % reserror2f
    print "Number of request errors in Store 3: %d" % reqerror3f
    print "Number of response errors in Store 3: %d" % reserror3f
    print "----------------------------------------------------------------------------"


def datareplystorestats(packsize1f, packsize2f, packsize3f, tot1=0,
                        tot2=0, tot3=0):     # Store the packet sizes of dns responses

    for a in packsize1f:
        tot1 += a
    ma1 = max(packsize1f)
    mi1 = min(packsize1f)
    av1 = np.mean(packsize1f)
    sd1 = np.std(packsize1f)

    for a in packsize2f:
        tot2 += a
    ma2 = max(packsize2f)
    mi2 = min(packsize2f)
    av2 = np.mean(packsize2f)
    sd2 = np.std(packsize2f)

    for a in packsize3f:
        tot3 += a
    ma3 = max(packsize3f)
    mi3 = min(packsize3f)
    av3 = np.mean(packsize3f)
    sd3 = np.std(packsize3f)

    print "----------------------------------------------------------------------------"
    print "Bytes of dat in Store 1:"
    print "Total number of Bytes: %d" % tot1
    print "Max value: %d" % ma1
    print "Min value: %d" % mi1
    print "Average value: %d" % av1
    print "Standard deviation: %d" % sd1
    print "--"
    print "Bytes of dat in Store 2:"
    print "Total number of Bytes: %d" % tot2
    print "Max value: %d" % ma2
    print "Min value: %d" % mi2
    print "Average value: %d" % av2
    print "Standard deviation: %d" % sd2
    print "--"
    print "Bytes of dat in Store 3:"
    print "Total number of Bytes: %d" % tot3
    print "Max value: %d" % ma3
    print "Min value: %d" % mi3
    print "Average value: %d" % av3
    print "Standard deviation: %d" % sd3
    print "----------------------------------------------------------------------------"


def avrstd(dicto, storeid):      # Requires a dictionary to calculate the Average and Standard deviation
    lista = []
    for di in dicto:
        if len(dicto[di]) == 3:
            lista.append(dicto[di][2])

    average = np.mean(lista)        # Mean
    std = np.std(lista)             # Standard deviation
    minlista = min(lista)           # Lowest value
    maxlista = max(lista)           # Highest value

    print "--------------------------------------------------------------------------"
    print "Average and Std. statistics of store %d" % storeid
    print "Average: %f" % average
    print "Standard deviation: %f" % std
    print "Max: %f" % maxlista
    print "Min: %f" % minlista
    print "--------------------------------------------------------------------------"

    return average, std, lista


def avrstdplot(arr2, arr3, arrb=np.array([1, 2, 3]), arra = np.array(["Unbound", "Bind", "PowerDNS"])):  # Requires two arrays/integers for plotting the x,y and std
    global path, fil

    plt.xticks(arrb, arra)
    plt.errorbar(arrb, arr2, yerr=arr3, ecolor='brown', linestyle='None', color='k',
                 marker='s', elinewidth='2', capsize=15, capthick=2)       # x-axes, y-axes and std
    plt.title(r'Mean/Std. DNS Resolvers')
    plt.ylabel('Average and Standard Deviation')
    x1, x2, y1, y2 = plt.axis()
    plt.axis((0, 4, y1, y2))
    plt.grid(True, axis='both', linewidth='2')
    plt.savefig(path + fil + 'avgstd.png')


def barplot(nrs, maxnr, storeid):
    global path, fil

    som = sum(nrs)
    textsom = "Total: " + str(int(som))
    fig2 = plt.figure(2, figsize=(18, 10))
    xlabels = ["0", "0.001", "0,002", "0,004", "0,008", "0.016", "0.031", "0.063", "0.125", "0.25", "0.5", "1", "2", "4", "8", "16",
               "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    xticksb = range(1, len(xlabels)+1)
    plt.title('Histogram Response times ' + storeid)
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Number of queries')
    plt.yscale('log')

    # decide the range of the y axis
    if maxnr < 10:
        yax = 10
    elif maxnr < 100:
        yax = 100
    elif maxnr < 1000:
        yax = 1000
    elif maxnr < 10000:
        yax = 10000
    elif maxnr < 100000:
        yax = 100000
    elif maxnr < 1000000:
        yax = 1000000

    plt.ylim(0.1, yax)
    plt.bar(range(1, len(nrs)+1), nrs, width=0.9, color='#4343FF', log=True)
    plt.xticks(xticksb, xlabels)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((0, len(nrs)+1, y1, y2))
    plt.grid(True, linewidth='2')
    plt.legend([textsom], loc=1)
    plt.savefig(path + fil + storeid + 'histogram.png')
    plt.close(fig2)

def barplotmerge(nrs1, nrs2, nrs3, maxnr):  # This histogram shows data of max. three resolvers
    global path, fil

    som1 = sum(nrs1)
    som2 = sum(nrs2)
    som3 = sum(nrs3)
    textsom1 = "Unbound Total: " + str(int(som1))
    textsom2 = "BIND Total: " + str(int(som2))
    textsom3 = "PowerDNS Total: " + str(int(som3))

    fig3 = plt.figure(3, figsize=(18, 10))
    xlabels = ["0", "0.001", "0,002", "0,004", "0,008", "0.016", "0.031", "0.063", "0.125", "0.25", "0.5", "1", "2", "4", "8", "16",
               "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    xticksb = range(1, len(xlabels)+1)
    plt.title('Histogram Response times resolvers')
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Number of queries')
    plt.yscale('log')

    if maxnr < 10:
        yax = 10
    elif maxnr < 100:
        yax = 100
    elif maxnr < 1000:
        yax = 1000
    elif maxnr < 10000:
        yax = 10000
    elif maxnr < 100000:
        yax = 100000
    elif maxnr < 1000000:
        yax = 1000000

    plt.ylim(0.1, yax)
    plt.bar(np.arange(1, len(nrs1)+1), nrs1, width=0.33, color='#4343FF', log=True)
    plt.bar(np.arange(1.3, len(nrs2)+1), nrs2, width=0.33, color='#43FF43', log=True)
    plt.bar(np.arange(1.6, len(nrs3)+1), nrs3, width=0.33, color='#FF4343', log=True)
    plt.xticks(xticksb, xlabels)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((0, len(nrs1)+1, y1, y2))
    plt.rcParams['font.size'] = 14
    plt.grid(True, linewidth='2')
    plt.legend([textsom1, textsom2, textsom3], loc=1)
    plt.savefig(path + fil + 'mergehistogram.png')
    plt.close(fig3)

def barplotsplit(nrsnoerr, nrsserv, nrsnx, maxnr, storeid):  # This histogram shows data of a single resolver split in RTYPE
    global path, fil
    somnoerr = sum(nrsnoerr)
    somserv = sum(nrsserv)
    somnx = sum(nrsnx)
    somtemp = [somnoerr, somserv, somnx]
    som = sum(somtemp)
    textsomnoerr = "No Error" + "Total: " + str(int(somnoerr))
    textsomserv = "ServFail" + "Total: " + str(int(somserv))
    textsomnx = "NX Domain" + "Total: " + str(int(somnx))

    fig2 = plt.figure(2, figsize=(18, 10))
    xlabels = ["0", "0.001", "0,002", "0,004", "0,008", "0.016", "0.031", "0.063", "0.125", "0.25", "0.5", "1",
               "2", "4", "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    xticksb = range(1, len(xlabels)+1)
    plt.title('Histogram Response times ' + storeid)
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Number of queries')
    plt.yscale('log')

    if maxnr < 10:
        yax = 10
    elif maxnr < 100:
        yax = 100
    elif maxnr < 1000:
        yax = 1000
    elif maxnr < 10000:
        yax = 10000
    elif maxnr < 100000:
        yax = 100000
    elif maxnr < 1000000:
        yax = 1000000

    plt.ylim(0.1, yax)
    plt.bar(range(1, len(nrsnoerr)+1), nrsnoerr, width=1, color='#4343ff', log=True, label=textsomnoerr)
    plt.bar(range(1, len(nrsserv)+1), nrsserv, width=1, color='#ff4343', log=True, label=textsomserv, bottom=nrsnoerr)
    plt.bar(range(1, len(nrsnx)+1), nrsnx, width=1, color='#43ff43', log=True, label=textsomnx, bottom=[i+j for i, j in zip(nrsnoerr, nrsserv)])
    plt.xticks(xticksb, xlabels)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((0, len(nrsnoerr)+1, y1, y2))
    plt.grid(True, linewidth='2')
    plt.legend(loc=1)
    plt.savefig(path + fil + storeid + 'sephistogram.png')
    plt.close(fig2)


def barplotdistsplit(nrsnoerr, nrsserv, nrsnx, storeid):
    global path, fil
    nrspernoerr = []
    nrsperserv = []
    nrspernx = []

    somnoerr = sum(nrsnoerr)
    somserv = sum(nrsserv)
    somnx = sum(nrsnx)
    somtemp = [somnoerr, somserv, somnx]
    som = sum(somtemp)

    textsomnoerr = "No Error" + "Total: " + str(int(somnoerr))
    textsomserv = "ServFail" + "Total: " + str(int(somserv))
    textsomnx = "NX Domain" + "Total: " + str(int(somnx))

    fig3 = plt.figure(3, figsize=(18, 10))
    xlabels = ["0", "0.001", "0,002", "0,004", "0,008", "0.016", "0.031", "0.063", "0.125", "0.25", "0.5", "1", "2", "4", "8", "16",
               "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    xticksb = range(1, len(xlabels)+1)
    yticksb = range(0, 51, 10)
    plt.title('Response time Distribution ' + storeid)
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Percentage/Distribution')
    # plt.yscale('log')

    for nrnoerr in nrsnoerr:
        temp = (nrnoerr / som) * 100
        temp = round(temp, 2)
        nrspernoerr.append(temp)

    for nrserv in nrsserv:
        temp = (nrserv / som) * 100
        temp = round(temp, 2)
        nrsperserv.append(temp)

    for nrnx in nrsnx:
        temp = (nrnx / som) * 100
        temp = round(temp, 2)
        nrspernx.append(temp)

    plt.ylim(0, 55)
    plt.bar(range(1, len(nrsnoerr)+1), nrspernoerr, width=1, color='#4343ff', label=textsomnoerr)
    plt.bar(range(1, len(nrsserv)+1), nrsperserv, width=1, color='#ff4343', label=textsomserv, bottom=nrspernoerr)
    plt.bar(range(1, len(nrsnx)+1), nrspernx, width=1, color='#43ff43', label=textsomnx, bottom=[i+j for i, j in zip(nrspernoerr, nrsperserv)])

    plt.xticks(xticksb, xlabels)
    plt.yticks(yticksb)
    plt.grid(True, linewidth='2')
    plt.legend(loc=1)
    plt.savefig(path + fil + storeid + 'sepdistribution.png')
    plt.close(fig3)


def barplotdist(nrs, storeid):
    global path, fil
    nrsper = []
    som = sum(nrs)
    textsom = "Total: " + str(int(som))
    fig3 = plt.figure(3, figsize=(18, 10))
    xlabels = ["0", "0.001", "0,002", "0,004", "0,008", "0.016", "0.031", "0.063", "0.125", "0.25", "0.5", "1", "2",
               "4", "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    xticksb = range(1, len(xlabels)+1)
    yticksb = range(0, 51, 5)
    plt.title('Response time Distribution ' + storeid)
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Percentage/Distribution')
    # plt.yscale('log')

    for nr in nrs:
        temp = (nr / som) * 100
        temp = round(temp, 2)
        nrsper.append(temp)

    plt.ylim(0, 55)
    plt.bar(range(1, len(nrs)+1), nrsper, width=1, color='#4343FF')
    plt.xticks(xticksb, xlabels)
    plt.yticks(yticksb)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((0, len(nrs)+1, y1, y2))
    plt.grid(True, linewidth='2')
    plt.legend([textsom], loc=1)
    plt.savefig(path + fil + storeid + 'distribution.png')
    plt.close(fig3)


def histobarplot(store):
    global path, fil

    bins = [0, 0.000976563, 0.001953125, 0.00390625, 0.0078125, 0.015625, 0.03125, 0.0625, 0.125, 0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    xticksh = [0, 0.000976563, 0.001953125, 0.00390625, 0.0078125, 0.015625, 0.03125, 0.0625, 0.125, 0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    # xlabels = ["0", "0.1", "0.2", "0.3", "0.4", "0.5", "1", "2", "4", "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "4096"]
    # xticksb = range(1, len(xlabels)+1)
    # weights = np.ones_like(store)/len(store)
    # weights=weights,
    fig1 = plt.figure()
    n, bans, patch = plt.hist(store, bins, histtype='bar', color='#a4d11b', align='mid')
    plt.xticks(xticksh)
    plt.title('Histogram Resolver')
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Number of queries')
    plt.figure(2, figsize=(15, 10))
    plt.yscale('log')
    plt.ylim(0.1, 1000000)
    plt.bar(range(1, len(n)+1), n, width=1, color='red', log=True)
    # plt.xticks(xticksb, xlabels)
    # plt.savefig(path + fil + 'delete.png', orientation="landscape")
    plt.close(fig1)
    return n


def histogramplot(store, bins=1000):

    weights = np.ones_like(store)/len(store)
    #
    plt.hist(store, bins, weights=weights, histtype='stepfilled', color='#a4d11b', align='mid')
    x1, x2, y1, y2 = plt.axis()
    # x1 *= 0.9                                       # To broaden the view in the plot
    # x2 *= 1.1
    # y1 *= 0.9
    y2 *= 1.1
    plt.axis((x1, x2, y1, y2))
    plt.title('Histogram Resolver')
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Number of queries')
    # plt.savefig('/home/hamza/pcap/figures/unbound.png')
    plt.show()

    return


def boxplot(arr):                           # Boxplot, do not know yet whether necessary

    plt.boxplot(arr)
    plt.show()


def pdf(avr, std, arr):                       # The Probability Density Function shows the density of values

    plt.figure()
    arr.sort()
    plt.plot(arr, norm.pdf(arr, avr, std), 'r-', lw=3, alpha=0.9, label='norm pdf')

    # plt.plot(arr, mlab.normpdf(arr, avr, std))
    plt.show()


def cdf(f, g, h, n_bins):              # Should provide the average, std, the delta times and the number of bins
    n, bins, patches = plt.hist(h, n_bins, normed=1, histtype='step', cumulative=True)
    y = mlab.normpdf(bins, f, g).cumsum()
    y /= y[-1]
    plt.plot(bins, y, 'k--', linewidth=1.5)

    plt.show()
    # http://matplotlib.org/1.4.0/examples/statistics/histogram_demo_cumulative.html


def scttr():            # This one could be used to compare resolvers
    pass

fle = readfile(sys.argv)

pcap = dpkt.pcap.Reader(fle)


for ts, pckt in pcap:
    countall += 1                       # Count all packets, can also be used for debugging

    frame = ethdata(pckt)
    if frame.type != 0x0800:
        continue

    packet = ipdata(frame)
    if packet.p != 17:                  # Only allow and count UDP packets
        continue
    else:
        countudp += 1

    datagram = udpdata(packet)

    if datagram.sport or datagram.dport == 53:  # Only allow and count DNS packets
        pass
    else:
        continue

    application = dnsdata(datagram)

    if re.search("localhost$", application.qd[0].name):
        continue

    if re.search("1\.0\.0\.127\.dnsbugtest\.1\.0\.0\.127\.in-addr\.arpa", application.qd[0].name):
        continue

    countdns += 1

    if application.qr == 0:

        # if application.qd[0].type == 33:
        #     pass
        # else:
        #     continue

        iden = (application.id, datagram.sport, socket.inet_ntoa(packet.dst), application.qd[0].type, application.qd[0].name)

        # Check if domain name is already present in Trace dictionary
        # In order to trace back or perform statistics
        if application.qd[0].name not in trace:
            trace[application.qd[0].name] = [iden]

        else:
            trace[application.qd[0].name].append(iden)

        # Store data in correct dictionary based on Resolver
        if socket.inet_ntoa(packet.dst) == "192.168.1.11":
            typelist.append(application.qd[0].type)                 # Collect type of queries

            if iden not in store1:                                  # Check whether ID is already present.
                store1[iden] = [float(ts)]
            else:
                print "Request Error: Key already present %d" % countall
                reqerror1 += 1
                print iden
                continue

        elif socket.inet_ntoa(packet.dst) == "192.168.1.12":
            if iden not in store2:
                store2[iden] = [float(ts)]
            else:
                print "Request Error: Key already present %d" % countall
                reqerror2 += 1
                print iden
                continue

        elif socket.inet_ntoa(packet.dst) == "192.168.1.13":
            if iden not in store3:
                store3[iden] = [float(ts)]
            else:
                print "Request Error: Key already present %d" % countall
                reqerror3 += 1
                print iden
                continue

    elif application.qr == 1:

        # if application.rcode != 0:
        #     continue

        # if application.qd[0].type != 1:
        #     continue
        # Only no-error and A records
        # if application.qd[0].type == 33:
        #     pass
        # else:
        #     continue

        iden = (application.id, datagram.dport, socket.inet_ntoa(packet.src), application.qd[0].type, application.qd[0].name)

        # adflagtemp = str(dnsaddata(pckt))
        # if adflagtemp == "0":
        #     continue
        # elif adflagtemp == "1":
        #     writetotextfile(str(iden[0:2]) + str(iden[3:5]))

        if socket.inet_ntoa(packet.src) == "192.168.1.11":

            packsize1.append(datagram.ulen)                                   # Store packet size of udp datagram
            opcodelist1.append(application.opcode)
            rcodelist1.append(application.rcode)
            adflag1 += 1 if dnsaddata(pckt) == "1" else 0

            if iden in store1:
                if len(store1[iden]) == 1:                                    # Check for duplicate answers
                    store1[iden].append(float(ts))
                    temptime1 = store1[iden][1] - store1[iden][0]
                    store1[iden].append(temptime1)

                    if application.rcode == 0:
                        noerrorlist1.append(temptime1)

                    elif application.rcode == 2:
                        nnerr1 += 1
                        servlist1.append(temptime1)

                    elif application.rcode == 3:
                        nnerr1 += 1
                        nxlist1.append(temptime1)

                    if dnsaddata(pckt) == "1":
                        adlist1.append(temptime1)

                else:
                    print "Response Error: Response already stored, duplicate response %d" % countall
                    reserror1 += 1
                    print iden
                    continue

            else:
                print "Response Error: Key does not exist, check for request %d" % countall
                reserror1 += 1
                print iden

        elif socket.inet_ntoa(packet.src) == "192.168.1.12":

            packsize2.append(datagram.ulen)                                   # Store packet size of udp datagram
            opcodelist2.append(application.opcode)
            rcodelist2.append(application.rcode)
            adflag2 += 1 if dnsaddata(pckt) == "1" else 0

            if iden in store2:
                if len(store2[iden]) == 1:                                    # Check for duplicate answers
                    store2[iden].append(float(ts))
                    temptime2 = store2[iden][1] - store2[iden][0]
                    store2[iden].append(temptime2)

                    if application.rcode == 0:
                        noerrorlist2.append(temptime2)

                    elif application.rcode == 2:
                        nnerr2 += 1
                        servlist2.append(temptime2)

                    elif application.rcode == 3:
                        nnerr2 += 1
                        nxlist2.append(temptime2)

                    if dnsaddata(pckt) == "1":
                        adlist2.append(temptime2)

                else:
                    print "Response Error: Response already stored, duplicate response %d" % countall
                    reserror2 += 1
                    print iden
                    continue

            else:
                print "Response Error: Key does not exist, check for request %d" % countall
                reserror2 += 1
                print iden

        elif socket.inet_ntoa(packet.src) == "192.168.1.13":

            packsize3.append(datagram.ulen)                                   # Store packet size of udp datagram
            opcodelist3.append(application.opcode)
            rcodelist3.append(application.rcode)
            adflag3 += 1 if dnsaddata(pckt) == "1" else 0

            if iden in store3:
                if len(store3[iden]) == 1:                                    # Check for duplicate answers
                    store3[iden].append(float(ts))
                    temptime3 = store3[iden][1] - store3[iden][0]
                    store3[iden].append(temptime3)

                    if application.rcode == 0:
                        noerrorlist3.append(temptime3)

                    elif application.rcode == 2:
                        nnerr3 += 1
                        servlist3.append(temptime3)

                    elif application.rcode == 3:
                        nnerr3 += 1
                        nxlist3.append(temptime3)
                else:
                    print "Response Error: Response already stored, duplicate response %d" % countall
                    reserror3 += 1
                    print iden
                    continue

            else:
                print "Response Error: Key does not exist, check for request %d" % countall
                reserror3 += 1
                print iden

    else:
        nonreqres += 1

# -------------------------------------------------------------------

print "Step 1"
numberofstats(countall, countudp, nonreqres, trace, reqerror1, reserror1, reqerror2, reserror2, reqerror3, reserror3)
storestats(store1, 1)
storestats(store2, 2)
storestats(store3, 3)
namestorestats(trace)
typestorestats(typelist)
flagstorestats(opcodelist1, rcodelist1, 1)
flagstorestats(opcodelist2, rcodelist2, 2)
flagstorestats(opcodelist3, rcodelist3, 3)
# datareplystorestats(packsize1, packsize2, packsize3)
a, b, ab = avrstd(store1, 1)
c, d, cd = avrstd(store2, 2)
e, f, ef = avrstd(store3, 3)
avv = [a, c, e]
stdd = [b, d, f]
# , e , f

avrstdplot(avv, stdd, arrb=np.array([1, 2, 3]), arra=np.array(["Unbound", "Bind", "PowerDNS"]))

print "Step 2"
numb1 = histobarplot(ab)
numb2 = histobarplot(cd)
numb3 = histobarplot(ef)
maxnumb = max(max(numb1), max(numb2), max(numb3))
# ,
# --------------------------------------------------
print "Step 3"
numb11 = histobarplot(noerrorlist1)
numb12 = histobarplot(servlist1)
numb13 = histobarplot(nxlist1)
numb21 = histobarplot(noerrorlist2)
numb22 = histobarplot(servlist2)
numb23 = histobarplot(nxlist2)
numb31 = histobarplot(noerrorlist3)
numb32 = histobarplot(servlist3)
numb33 = histobarplot(nxlist3)

# for i in numb11:
#     numb12.append(0)
#     numb22.append(0)


print "Step 4"
barplotsplit(numb11, numb12, numb13, maxnumb, "Unbound")
barplotdistsplit(numb11, numb12, numb13, "Unbound")
barplotsplit(numb21, numb22, numb23, maxnumb, "BIND")
barplotdistsplit(numb21, numb22, numb23, "BIND")
barplotsplit(numb31, numb32, numb33, maxnumb, "PowerDNS")
barplotdistsplit(numb31, numb32, numb33, "PowerDNS")

# -----------------------------------------------------
print "Step 5"
numb1 = histobarplot(ab)
print numb1
numb2 = histobarplot(cd)
print numb2
numb3 = histobarplot(ef)
print numb3
maxnumb = max(max(numb1), max(numb2), max(numb3))
#
barplot(numb1, maxnumb, "Unbound")
barplotdist(numb1, "Unbound")
barplot(numb2, maxnumb, "BIND")
barplotdist(numb2, "BIND")
barplot(numb3, maxnumb, "PowerDNS")
barplotdist(numb3, "PowerDNS")
print "Step 6"
barplotmerge(numb1, numb2, numb3, maxnumb)
# -------------------------------------------------------
print "Step 7"
numbad1 = histobarplot(adlist1)
numbad2 = histobarplot(adlist2)

maxnumbad = max(max(numbad1), max(numbad2))
barplot(numbad1, maxnumbad, "Unbound DNSSEC")
barplotdist(numbad1, "Unbound DNSSEC")
barplot(numbad2, maxnumbad, "BIND DNSSEC")
barplotdist(numbad2, "BIND DNSSEC")

print "Step Finish"
print adflag1
print adflag2
print adflag3