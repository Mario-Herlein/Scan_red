'''
Script para escanear un red dentro de un entorno Linux.

Permite analizar las IP de la red en la que se encuentre tu máquina, en una determinada interfaz, indicada por el usuario. 

La ejecución se debe realizar en un entorno Linux con las librerias instaladas y actualizadas de scapy, socket, json, requests, time y nmap. 

Una vez haya encontrado las IP, muestra los puertos que tiene abiertos, tanto para TCP como para UDP, y junto al puerto, se indica el banner del servicio, utilizando 

la técnica de Banner Grabbing. Además, el resultado se codifica en formato JSON y envia mediante una petición POST a la url:

 http://127.0.0.1/example/fake_url.php es una URL falsa, y que no responderá a la petición.
'''
import scapy.all as scapy
import socket
import json
import requests
import time
import nmap


def main():
    '''Permite el ingreso manual de la IP a escanear y retorna la IP validada'''

    ip=input("\nIngrese la dirección IP de la red a escanear:")
    validador= chequeo_ip(ip)
    while not validador:
        ip=input("\nLa dirección IP no existe, ingrese nuevamente: ")
        validador=chequeo_ip(ip)
    return ip
    

def chequeo_ip(IP):
    '''Divide por octetos una ip y valida la misma'''
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


def scan(ip):
    ''' Escanea una red acorde a una IP ingresada considerando una mascara de red 255.255.255.0
    devuelve un diccionario con las IP conectadas a esa red'''
    ip=ip+"/24"

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
    
    '''Escanea los puertos de una IP ingresada.
    -Imprime en pantalla los puertos abiertos correspondientes a esa IP
    distinguiendo entre los puertos de protocolos TCP y UDP, incluyendo 
    el banner de cada puerto luego de llamar la función bannergrabbing().
    -Devuelve un diccionario con la IP y los puertos abiertos correspondientes a esa IP
    distinguiendo entre los puertos de protocolos TCP y UDP.'''
    
    nm = nmap.PortScanner()
    results = nm.scan(hosts=ip,arguments="-sS -sU -n -Pn -T4")
    puertos_abiertos=""
    count=0
    puertos_ip={}
    for proto in nm[ip].all_protocols():
        print(f"\n     {proto.upper()}:")
        print()
        print ("      Puertos abiertos:        Banner:")
        lport = nm[ip][proto].keys()
        sorted(lport)
        for port in lport:
            banner=bannergrabbing(ip,port)
            print (f"{port:>28}{banner:>18}")
            if count==0:
                puertos_abiertos=puertos_abiertos+str(port)
                count=1
            else:
                puertos_abiertos=puertos_abiertos+","+str(port)
    puertos_ip["Dirección IP"]= str(ip)
    puertos_ip["Puertos"]=puertos_abiertos
    return puertos_ip


def bannergrabbing(host,port):
    
    ''' Busca el banner de un determinado puerto correspondiente a una IP
    Devuelve el banner de ese puerto analizado, en caso de no encontrarlo devuelve UNKNOW'''

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(( str(host), int(port) ))
        socket.settimeout(1)
        banner = sock.recv(1024)
        return banner
    except Exception as e:
        banner= "UNKNOWN" 
        return banner


def display_result(result,IP):
   
    ''' Imprime en pantalla las IP encontradas en la red analizada
        Llama a la función scanport()
        Crea una lista de diccionarios de IP y puertos encontrados
        Genera un archivo output.json que envia a la URL  "http://127.0.0.1/example/fake_url.php"
        Imprime en pantalla la generacion y envio del archivo.
        Imprime en pantalla el error de la URL de envio.
    '''

    IPyPuertos=[]
    print("\nLa busqueda puede llevar unos minutos ")
    print(f"\nAnalizando conexiones de la red {IP}/24 . . .")
    print()
    if len(result)==0:
        print("\nNo existen otras máquinas conectadas en esta red")
    else:
        for i in result:
            print(f"\nDireccion IP {i['ip']}\n======================")
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
            print("\nLa URL seleccionada para el envio del archivo, es invalida")
    return
        

IP =main()
result = scan(IP)
display_result(result,IP)