#-----------------------------------------------------
#--  Génération de configuration de routeur Mikrotik
#--  
#--   structure du fichier json
#--  {
# --     "psw" : mot de passe du routeur
#--      "wireguardAdd": adresse interface wireguard,
#--      "trunkName": nom du bridge (defaut trunk),
#--      "name": nom du routeur,
#--      "ports": tableau des ports physiques rattaché au trunk (ex. ["ether4","ether5","ether3"]),
#--      "dsn": liste des dns a utiliser (@ip uniquement defaut "8.8.8.8"),
#--      "allowedInterfaceList": liste des interfaces sortantes autorisée par défaut
#--      "allowedVlan": liste des vlans autorisés par défaut
#--      "ipPoolStart": debut du pool "local", la fin est broadcast-1 (defaut 192.168.87.30)
#--      "mngtVlan": id du vlan défaut=-1> conserver l'existant,
#--      "vlans": tableau des vlans a créer
#--      [
#--          {
#--             "name": nom du vlan "commun", 
#--             "id": id du vlan 6,
#--             "dns": écrase la liste des dns (ip séparées par des virgules),
#--             "netmask": netmask à utiliser (defaut 24)
#--             "ipPoolStart": ip permettant de déterminer la 1er 
#--                             adresse du pool de d'ip dhcp racine 
#--                             défaut : 192.168.<id>.30
#--             "allowedVlan" : liste des vlan avec lesquels ce vlan peut communiquer
#--             "allowedInterfaceList" : tableau des listes d'interfaces avec lesquelles ce VLAN peut communiquer
#--                                      défaut : WAN pour accès internet
#--          },
#--      ]
#--  }
#--  
#-- work based on : https://forum.mikrotik.com/viewtopic.php?t=143620&sid=66528b8a74f80428d7c31d0c48966f56 
#-- 
#-----------------------------------------------------


from io import TextIOWrapper
import ipaddress
import json
from datetime import datetime
import commun
import os



class PortData:
    def __init__(self, elt:dict, vlans:dict) -> None:
        if "type" not in elt:
            self.valid=False
            self.cause="type is mandatory"
            return
        self.type=elt["type"]
        if self.type=="access":
            if "vlan" not in elt:
                self.valid=False
                self.cause="vlan mandatory for access"
                return
            else:
                self.vlan=elt["vlan"]
                if self.vlan not in vlans:
                    self.valid=False
                    self.cause="unknown vlan"
                    return
        elif self.type == "trunk":
            self.vlan=""
        else:
            self.valid=False
            self.cause="unknown type"
            return
        self.valid=True

class VlansData:
    def __init__(self, elt:dict, common:dict) -> None:
        if "name" not in elt:
            self.valid=False
            self.cause="name is mandatory"
            self.name=""
            return
        else:
            self.name=elt["name"]
        if "id" not in elt:
            self.valid=False
            self.cause="id is mandatory"
            self.id=""
            return
        else:
            self.id=elt["id"]
        self.valid=True
        if "dns" in elt:
            self.dns=elt["dns"]
        else:
            self.dns=common["dns"]
        if "ipPoolStart" in elt:
            self.ipPoolStart = elt["ipPoolStart"]
        else:
            self.ipPoolStart = "192.168.%s.30" % (self.id)
        if "allowedVlan" in elt:
            self.allowedVlan = elt["allowedVlan"]
        else:
            self.allowedVlan=common["allowedVlan"]
        if "allowedInterfaceList" in elt:
            self.allowedInterfaceList = elt["allowedInterfaceList"]
        else:
            self.allowedInterfaceList = common["allowedInterfaceList"]
        if "netmask" in elt:
            self.netmask=elt["netmask"]
        else:
            self.netmask=24


trunkName:str="bridge"
f:TextIOWrapper=None
comment:str=""
common:dict


def main():
    descriptorFn = commun.getArgv("-process", '/home/oec/DEV/Mikrotik/private/pontcarre/servicesTech/routeur.json')
    if ( len(descriptorFn) == 0 ):
        print("-process is mandatory")
        return
    fn = commun.getArgv("-toFile", '')
    if ( len(fn) == 0 ):
        fn, ext = os.path.splitext(descriptorFn)
        fn = fn + '.rsc'
        print("result will be writen to %s" % (fn) )

    global comment
    comment = commun.getArgv("-comment", "ohmi")


    descriptor = commun.dataLoad(descriptorFn)
    if ( len(descriptor) == 0 ):
        print("file %s is empty" % (descriptorFn) )
        return

    j = json.loads(descriptor)
    # global trunkName
    # trunkName = j["trunkName"]

    global f
    f = open(fn, 'w')

    common=getCommon(j)
    cartouche(descriptorFn)
    setLan(j)
    setBasis(j)
    setWireguard(j)

    vlans:dict = explodeVlans(j, common=common)
    ports:dict = explodePorts(j, vlans=vlans)
    
    genIngres(vlans=vlans, ports=ports)
    genEgres(vlans=vlans, ports=ports)

    genVlans(vlans=vlans)
    genFw(vlans=vlans)
    genSecurity(ports=ports)

    write('')
    write('/interface bridge set BR1 vlan-filtering=yes' )
    # write('/ip/firewall/filter/set [find comment="ohmi config"] disabled=yes' )
    f.close()

    return

def getCommon(j:dict)->dict:
    c = dict()
    if "dns" in j:
        c["dns"] = j["dns"]
    else:
        c["dns"]=["8.8.8.8"]
    if "allowedInterfaceList" in j:
        c["allowedInterfaceList"] = j["allowedInterfaceList"]
    else:
        c["allowedInterfaceList"] = ["WAN"]
    if "allowedVlan" in j:
        c["allowedVlan"] = j["allowedVlan"]
    else:
        c["allowedVlan"] = []
    return c

def explodePorts(j:dict, vlans:dict)->dict:
    ports = dict()
    if "ports" not in j:
        print('tag "ports" is mandatory')
        return ports
    for elt in j["ports"]:
        if "num" in elt:
            data=PortData(elt, vlans=vlans)
            for num in elt["num"]:
                if data.valid==False:
                    print("port:%s, invalid data type:%s, vlan:%s, cause:%s" % (num, data.type, data.vlan, data.cause) )
                else:
                    if num in ports:
                        print("port:%s is duplicated" % (num) )
                    else:
                        ports[num]=data
        else:
            print("num not found in elt")
    return ports


def explodeVlans(j:dict, common:dict)->dict:
    vlans=dict()
    if "vlans" in j:
        for elt in j["vlans"]:
            data = VlansData(elt, common=common)
            if data.valid==True:
                vlans[data.name] = data
            else:
                print("vlan:%s invalid cause:%s" % (data.name, data.cause) )
    for k,v in vlans.items():
        for a in v.allowedVlan:
            if a not in vlans:
                v.valid=False
                v.cause="allowedVlan not known"
            elif vlans[a].valid==False:
                v.valid=False
                v.cause="refers to invalid vlan def"
    tmp = dict()
    for k,v in vlans.items():
        if v.valid==True:
            tmp[k]=v
        else:
            print("cleaup vlan:%s invalid cause:%s" % (v.name, v.cause) )
    return tmp

def genIngres(vlans:dict, ports:dict)->bool:
    write('')
    write( '###########' )
    write( '# ingress #' )
    write( '###########' )
    write( '/interface/bridge/port' )
    
    for k,v in ports.items():
        pvid=""
        if v.type == "access":
            pvid="pvid=%s" % (vlans[v.vlan].id)  
        write( '  set bridge=%s %s [find interface=%s]' % (trunkName, pvid, k) )

def genEgres(vlans:dict, ports:dict)->bool:
    write('')
    write( '##########' )
    write( '# egress #' )
    write( '##########' )
    write( '/interface/bridge/vlan' )
    
    trunkPorts=""
    for k,v in ports.items():
        if v.type=="trunk":
            trunkPorts = "%s,%s" % (trunkPorts, k)

    for k,v in vlans.items():
        write( '  add interface=%s vlan-ids=%s tagged=%s%s' % (trunkName, v.id, trunkName, trunkPorts) )

def genVlans(vlans:dict)->bool:
    write('')
    write( '########' )
    write( '# VLAN #' )
    write( '########' )
    for k,v in vlans.items():
        interface = ipaddress.IPv4Interface(v.ipPoolStart+"/"+str(v.netmask))
        dns=""
        for d in v.dns:
            if len(dns) > 0:
                dns = dns + "," + d
            else:
                dns = d
        write( '# %s - %s' % (k, v.id) )
        write( '/interface vlan add interface=%s name=%s_vl vlan-id=%s comment="%s"' % (trunkName, k, v.id, comment) )
        write( '/ip address add interface=%s_vl address=%s/%d comment="%s"' % (k, interface.network[1], v.netmask, comment) )
        write( '/ip pool add name=%s_pool ranges=%s-%s comment="%s"' % (k, v.ipPoolStart, interface.network.broadcast_address-1, comment) )
        write( '/ip dhcp-server add address-pool=%s_pool interface=%s_vl name=%s_dhcp disabled=no comment="%s"' % (k, k, k, comment) )
        write( '/ip dhcp-server network add address=%s/%d dns-server=%s gateway=%s comment="%s"' % (interface.network.network_address, v.netmask, dns, interface.network[1], comment) )
    return True

def genFw(vlans:dict)->bool:
    write('')
    write( '############' )
    write( '# Firewall #' )
    write( '############' )
    for k,v in vlans.items():
        write( ('/interface/list/member add interface=%s_vl list=LAN comment="%s"' % (k, comment) ) )
        for elt in v.allowedVlan:
            write( ('/ip firewall filter add chain=forward action=accept in-interface=%s_vl out-interface=%s comment="%s"' % (k, elt, comment) ) )
        for elt in v.allowedInterfaceList:
            write( ('/ip firewall filter add chain=forward action=accept in-interface=%s_vl out-interface-list=%s comment="%s"' % (k, elt, comment) ) )

        write( ('/ip firewall filter add chain=forward action=drop in-interface=%s_vl comment="%s"' % (k, comment) ) )
    return True

def genSecurity(ports:dict)->bool:
    write('')
    write( '#################' )
    write( '# VLAN Security #' )
    write( '#################' )
    write( '/interface bridge port')
    for k,v in ports.items():
        if v.type == "trunk":
            write( '  set bridge=%s ingress-filtering=yes frame-types=admit-only-vlan-tagged [find interface=%s]' % (trunkName, k) )
        elif v.type == "access":
            write( '  set bridge=%s ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged [find interface=%s]' % (trunkName, k) )
        else:
            write( '  set bridge=%s ingress-filtering=yes frame-types=admit-all [find interface=%s]' % (trunkName, k) )


def write(s:str)->None:
    f.write('%s\n' % (s) )


def cartouche(fromFile:str):
    write(  '#######################################################################################')
    write(  '# configuration generated by ohmi')
    write(  '#     script:makeVlan.py')
    write( ('#     Source: %s' % (fromFile) ) )
    write( ('#     on: %s' % (datetime.now().strftime("%Y/%m/%d %H:%M:%S") ) ) )
    write(  '#     you may want to issue :')
    write(  '#        /system reset-configuration')
    write(  '#        /ip/firewall/filter add action=accept chain=input dst-port=23 protocol=tcp place-before=2 comment="ohmi config"' )
    write(  '#' )
    write(  '#     to get wireguard public key issue /interface/wireguard print' )
    write(  '#     to set wireguard peer public key issue /interface/wireguard/peers/ set public-key="uHXS0oX5IPfuPbo28ztqAYfxLDGaggpfKOXYckF5nTc=" [find interface=wireguard1]' )
    write(  '#' )
    write(  '#######################################################################################')


def setBasis(j:dict)->bool:
    name=""
    psw=""
    if "name" in j:
        name=j["name"]
    else:
        print('tag "name" is mandatory')
        return False
    if "psw" in j:
        psw=j["psw"]
    else:
        print('tag "psw" is mandatory')
        return False
    write('')
    write( '#########################' )
    write( '# Generic configuration #' )
    write( '#########################' )
    write( ('/system identity set name="%s"' % (name) ) )
    write( ('/user/set [find name="admin"] password=%s' % (psw) ) )
    # write( ('/interface bridge add name=%s protocol-mode=none vlan-filtering=no comment="%s"' % (trunkName, comment) ) )
    write( ('/interface list add name=VLAN comment="%s"' % (comment)) )
    # write( ('/ip/firewall/filter add action=accept chain=input dst-port=8291 protocol=tcp place-before=2 disabled=yes comment="%s winbox"' % (comment)) )
    # write( ('/ip/firewall/filter add action=accept chain=input dst-port=23 protocol=tcp place-before=2 disabled=yes comment="%s telnet"' % (comment)) )
    write( '/ip/cloud/set ddns-enabled=yes' )

    return True

# reset lan
def setLan(j:dict)->bool:
    ipPoolstart=""
    if "ipPoolStart" in j:
        ipPoolstart=j["ipPoolStart"]
    else:
        ipPoolstart="192.168.87.30"
    interface = ipaddress.IPv4Interface(ipPoolstart+"/24")
    netAddr = interface.network.network_address
    rtrAddr = interface.network.network_address+1
    write('')
    write( '#####################' )
    write( '# LAN configuration #' )
    write( '#####################' )
    write( ('/ip/pool/set [find name=default-dhcp] ranges=%s-%s comment="%s LAN"' % (ipPoolstart, interface.network.broadcast_address-1, comment)) )
    write( ('/ip/address/set [find comment="defconf"] address=%s/24 interface=bridge network=%s comment="%s LAN"' % (rtrAddr, netAddr, comment)) )
    write( ('/ip/dhcp-server/network/set [find comment="defconf"] address=%s/24 dns-server=%s gateway=%s netmask=24 comment="%s LAN"' % (netAddr, rtrAddr, rtrAddr ,comment)) )
    write( ('/ip/dns/static/set [find comment="defconf"] address=%s name=router.lan comment="%s LAN"' % (rtrAddr, comment)) )
    return True

def setWireguard(j:dict)->bool:
    wireguardAdd=""
    if "wireguardAdd" in j:
        wireguardAdd=j["wireguardAdd"]
    else:
        wireguardAdd="10.10.0.1"

    interface = ipaddress.IPv4Interface(wireguardAdd+"/24")
    write('')
    write( '###########################' )
    write( '# wireguard configuration #' )
    write( '###########################' )
    write( ('/interface/wireguard add listen-port=13231 name=wireguard1 comment="%s wireguard"' % (comment)) )
    write( ('/ip/firewall/filter add action=accept chain=input dst-port=13231 protocol=udp place-before=2 comment="%s wireguard"' % (comment)) )
    write( ('/ip/address add address=%s/24 interface=wireguard1 network=%s comment="%s wireguard"' % (wireguardAdd, interface.network.network_address, comment)) )
    write( ('/interface/list/member/add interface=wireguard1 list=LAN comment="%s wireguard"' % (comment)) )
    write( '/interface/wireguard/peers add allowed-address=10.10.0.2/32 interface=wireguard1 public-key="uHXS0oX5IPfuPbo28ztqAYfxLDGaggpfKOXYckF5nTc=" comment="routeur ohmi"' )
    return True



main()

