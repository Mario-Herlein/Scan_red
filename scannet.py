
import scapy.all as scapy
import socket
import json
import requests
import time


def main():
    ip=input("Ingrese la dirección IP de la red a escanear:")
    validador= chequeo_ip(ip)
    while not validador:
        ip=input("\nLa dirección IP no existe, ingrese nuevamente: ")
        validador=chequeo_ip(ip)
    netmask=int(input("Ingrese las mascara de red en notación CIDR: /"))
    validador= chequeo_netmask(netmask)
    while not validador:
        netmask=netmask=int(input("\nLa mascara de red es incorrecta, debe ser mayor a 1 y menor a 32.\nIngrese nuevamente: /"))
        validador=chequeo_netmask(netmask)
    return ip, netmask
    

def chequeo_ip(IP):
    try:
        octetos= IP.split('.')
        valid_ip = 0
        for i in octetos:
            if int(i) >= 0 and int(i) <= 255:
                valid_ip += 1
        if valid_ip == 4:
            return True
        else:
            return False
    except:
        return False


def chequeo_netmask(netmask):
    return 1<netmask<32


def scan(ip,netmask):
    ip=ip+"/"+str(netmask)

    arp_req_frame = scapy.ARP(pdst = ip)

    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    result = []
    for i in range(0,len(answered_list)):
        client_dict = {"ip" : answered_list[i][1].psrc}
        result.append(client_dict)
    return result

def scanport(ip):
    import nmap
    nm = nmap.PortScanner()
    results = nm.scan(hosts=ip,arguments="-n -Pn -T4")
    puertos_abiertos=""
    count=0
    puertos_ip={}
    for proto in nm[ip].all_protocols():
        print(f"        {proto.upper()}:")
        print()
        print ("        Puertos abiertos:")
        lport = nm[ip][proto].keys()
        sorted(lport)
        for port in lport:
            print (f"                          {port}")
            if count==0:
                puertos_abiertos=puertos_abiertos+str(port)
                count=1
            else:
                puertos_abiertos=puertos_abiertos+","+str(port)
    puertos_ip["Dirección IP"]= str(ip)
    puertos_ip["Puertos"]=puertos_abiertos
    return puertos_ip


def display_result(result,IP):
    IPyPuertos=[]
    print(f"\nBuscando otras máquinas en la red {IP}...")
    print()
    if len(result)==0:
        print("\nNo existen otras máquinas conectadas en esta red")
    else:
        for i in result:
            print(f"======================\nDireccion IP {i['ip']}\n======================")
            IPyPuertos.append(scanport(i['ip']))
    
    print("\nGenerando archivo output.json...")
    with open ("output.json","w+") as f:
        json.dump(IPyPuertos,f)
        print()
        print("Enviando archivo 'output.json' a http://127.0.0.1/example/fake_url.php...")
        try:
            r = requests.post("http://127.0.0.1/example/fake_url.php", files={'output.json': f})
            print(r.text)
        except:
            time.sleep(2)
            print("\n La URL seleccionada para el envio del archivo es invalida")
        

IP , netmask =main()
result = scan(IP,netmask)
display_result(result,IP)