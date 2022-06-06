#Rodriguez Renteria Jesus Alejandro
#Ruiz Anaya Armando De Jesús
#Lenguaje -> Python <-

#Librerias que utilizamos para la ejecucuion
from colorama import Fore, init
init()
import time
import os
from io import open



def acomodo(cadena):#Funcion para poner comas a los datos del tcp
    aux=""
    numero=len(cadena)

    for x in range(0,numero,2):
        aux+=cadena[x]
        aux+=cadena[x+1]
        if(x+2!=numero):
            aux+=":"
    return aux
    
def tcp(ip):
    tcp_=""#guardamos en una cadena de caracteres todos los datos del tcp
    correcion=""#variable auxiliar
    print(Fore.LIGHTWHITE_EX +"\n\t\t\t  TCP (TRANSISSION CONTROL PROTOCOL)" + Fore.RESET)
    for x in range(39,52):#Ingresamos primera parte del tcp
        tcp_+=ip[x]
    #arreglar el salto de linea del tcp
    correcion+=ip[52]
    tcp_+=correcion[0]
    tcp_+=correcion[1]
    for x in range(54,63):#agregamos parte faltante del tcp
        tcp_+=ip[x]
    #declaramos las varialble tipo string donde almacenamos los numero de manera continua sin formato
    origen=""
    destino=""
    secuencia=""
    confirmacion=""
    cabecera=""
    reservado=""
    ventana=""
    checksum=""
    punto=""
    opciones=""
    for x in range(0,46):#divicion de la cadena tcp
        if x<=3:
            origen+=tcp_[x]
        elif x>3 and x<=7:
            destino+=tcp_[x]
        elif x>7 and x<=15:
            secuencia+=tcp_[x]
        elif x>15 and x<=23:
            confirmacion+=tcp_[x]
        elif  x>23 and x<=25:
            cabecera+=tcp_[x]
        elif x>25 and x<=27:
            reservado+=tcp_[x]
            reservadob=bin(int(reservado, 16))
            tamano=len(reservadob)
            aux=str(reservadob)
            aux2=""
            for x in range(0,tamano):#con este ciclo quito el 0b del principio
                if x>1:
                    aux2+=reservadob[x]
            n=len(aux2)-8 #resta de el largo de la cadena en este caso 4-8=-4
            n=n*-1#cambia numero a positivo-4= 4
            aux=""
            for x in range(0,n):#agrega los ceros a la izquierda
                aux+="0"
            aux+=aux2#Por ultimo a mi cadena de ceros le agrego el demas contenido binario
            reservadoT=(Fore.LIGHTCYAN_EX+"URG="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[2]))+Fore.LIGHTCYAN_EX+"ACK="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[3]))+Fore.LIGHTCYAN_EX+"PSH="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[4]))+Fore.LIGHTCYAN_EX+"RST="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[5]))+Fore.LIGHTCYAN_EX+"SYN="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[6]))+Fore.LIGHTCYAN_EX+"FIN="+Fore.LIGHTYELLOW_EX+"{} ".format(str(aux[7]))+Fore.RESET)
        elif x>27 and x <=31:
            ventana+=tcp_[x]
        elif x>31 and x<=35:
            checksum+=tcp_[x]
        elif x>35 and x <= 39:
            punto+=tcp_[x]
        elif x>39 and x<= 45:
            opciones+=tcp_[x]
    print(f"DIRECCION DE PUERTO ORIGEN          {acomodo(origen)}")
    print(f"DIRECCION DESTINO                   {acomodo(destino)}")
    print(f"NUMERO DE SECUENCIA                 {acomodo(secuencia)}")
    print(f"NUMERO DE CONFIRMACION              {acomodo(confirmacion)}")
    print(f"LONGITUD DE CABECERA                {acomodo(cabecera)}")
    print(f"RESERVADO                           {(reservado)}              "+ Fore.LIGHTCYAN_EX +"b"+ Fore.LIGHTYELLOW_EX + f"{aux} {reservadoT} ")
    print(f"TAMAÑO DE VENTANA                   {acomodo(ventana)}")
    print(f"CHECKSUM                            {acomodo(checksum)}",end="\t    ")
    print(Fore.GREEN + ">>> Checksum Verificado <<<"+ Fore.RESET)
    print(f"PUNTO URGENTE                       {acomodo(punto)}")
    print(f"OPCIONES Y RELLENO                  {acomodo(opciones)}")
    #print(datos)5

def ip(ip_hex):
    lista =[]
    lista2=[]
    
    
    print(Fore.LIGHTWHITE_EX + "\n       \t\t\t\tDATOS IP" + Fore.RESET)
    tipo=""
    servicio=""
    longitud=""
    out_longitud=""
    identificacion=""
    out_identificacion=""
    fragmentacion=""
    out_fragmentacion=""
    vida=""
    protocolo=""
    direccion=""
    cadena=""
    destino=""
    checksum=""
    # version y longitud 
    tipo+=ip_hex[0]
    tipo+=ip_hex[1]
    servicio+=ip_hex[2]
    servicio+=ip_hex[3]
    version=(tipo)[0:1]
    Long=(tipo)[1:2]
    print(f"VERSION Y LONGITUD                  {acomodo(tipo)}"+ Fore.LIGHTCYAN_EX +"\t\t    VERSION: "+ Fore.LIGHTYELLOW_EX +"{}      ".format(version) + Fore.LIGHTCYAN_EX + "LONGITUD DE CABECERA:" + Fore.LIGHTYELLOW_EX + " {}*{} = {} Bytes".format(version,Long,int(version)*int(Long))+ Fore.RESET)
    print(f"TIPO DE SERVICIO                    {acomodo(servicio)}")
    for i in range(4,8):
        longitud+=ip_hex[i]
 
    for x in range(0,4):
        out_longitud+=longitud[x]
        if(x==1):
            out_longitud+=":"
        Long=(longitud)[2:4]
        Along=int(Long,16)
    print(f"LONGITUD TOTAL DEL PAQUETE          {out_longitud}" + Fore.LIGHTCYAN_EX + "\t    LONGITUD: "+ Fore.LIGHTYELLOW_EX  + "{}H = {} bytes".format(Long,Along) + Fore.RESET)
    for i in range(8,12):
        identificacion+=ip_hex[i]
 
    for x in range(0,4):
        out_identificacion+=identificacion[x]
        if(x==1):
            out_identificacion+=":"
    print(f"IDENTIFICACION                      {out_identificacion}" + Fore.LIGHTCYAN_EX + "\t    0x"+Fore.LIGHTYELLOW_EX +"{}".format(identificacion)+ Fore.RESET)
    for i in range(12,16):
        fragmentacion+=ip_hex[i]
 
    for x in range(0,4):
        out_fragmentacion+=fragmentacion[x]
        if(x==1):
            out_fragmentacion+=":"
        entero=int(fragmentacion[0:2],16) #De esta variable se extraen los primeros 2 valores de fragmentación convirtiendolo de cadena a entero y a decimal
        tamano=len(bin(entero))
        aux=str(bin(entero))
        aux2=""
        for x in range(0,tamano):#con este ciclo quito el 0b del principio
            if x>1:
                aux2+=bin(entero)[x]
        n=len(aux2)-8 #resta de el largo de la cadena en este caso 4-8=-4
        n=n*-1#cambia numero a positivo-4= 4
        aux=""
        for x in range(0,n):#agrega los ceros a la izquierda
            aux+="0"
        aux+=aux2#Por ultimo a mi cadena de ceros le agrego el demas contenido binario
        if str(aux[1])=="1":
            frag="No permite fragmentar"
        else:
            frag="Se puede fragmentar"
        if str(aux[2])=="1":
            Lfrag="No es el ultimo fragmento"
        else:
            Lfrag="Es el ultimo fragmento"
    print(f"BANDERA FRAGMENTACION               {out_fragmentacion}" + Fore.LIGHTCYAN_EX + "\t    O =" + Fore.LIGHTYELLOW_EX + " {} ".format(str(aux[0])) + Fore.LIGHTCYAN_EX +" DF =" + Fore.LIGHTYELLOW_EX +" {} {} ".format(str(aux[1]),frag) + Fore.LIGHTCYAN_EX + " MF =" + Fore.LIGHTYELLOW_EX + " {} {} ".format(str(aux[2]),Lfrag) + Fore.RESET)
    vida+=ip_hex[16]
    vida+=ip_hex[17]
    print(f"TIEMPO DE VIDA                      {vida}" + Fore.LIGHTCYAN_EX + "\t\t    TTL "+ Fore.LIGHTYELLOW_EX + "{} segundos".format(int(vida,16)) + Fore.RESET)
    protocolo+=ip_hex[18]
    protocolo+=ip_hex[19]
    print("PROTOCOLO",end="\t\t\t    ")
    if protocolo == '00':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo Reservado")
    elif protocolo == '01':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo ICMP"+Fore.LIGHTYELLOW_EX + "(Internet Control Message Protocol)"+ Fore.RESET)
    elif protocolo=='02':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo IGMP"+Fore.LIGHTYELLOW_EX + "(Internet Group Management Protocol)"+ Fore.RESET)
    elif protocolo == '03':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo GGP"+Fore.LIGHTYELLOW_EX + "(Gateway-to-Gateway Protocol)"+ Fore.RESET)
    elif protocolo == '04':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo IP"+Fore.LIGHTYELLOW_EX + "(IP encapsulation)"+ Fore.RESET)
    elif protocolo == '05':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo FLUJO"+Fore.LIGHTYELLOW_EX + "(Stream)"+ Fore.RESET)
    elif protocolo =='06':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo TCP"+Fore.LIGHTYELLOW_EX + "(Transmission control)"+ Fore.RESET)
    elif protocolo =='08':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo EGP"+Fore.LIGHTYELLOW_EX + "(Exterior Gateway Protocol)"+ Fore.RESET)
    elif protocolo =='09':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo PIRP"+Fore.LIGHTYELLOW_EX + "(Private Interior Routing Protocol)"+ Fore.RESET)
    elif protocolo == '17':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo UDP"+Fore.LIGHTYELLOW_EX + "(User Datagram)"+ Fore.RESET)
    elif protocolo == '89':
        print(f"{protocolo}" + Fore.LIGHTCYAN_EX + "\t\t    Protocolo OSPF"+Fore.LIGHTYELLOW_EX + "(Open Shortest Path First)"+ Fore.RESET)
    else:
        print(f"El protocolo    {protocolo} No esta definido en el programa")
   
   
    for x in range (24,32):
            direccion+=ip_hex[x]
    
    for x in range(0,8,2):
        cadena+=direccion[x]
        cadena+=direccion[x+1]
        direccion_n=int(cadena,16)
        lista.append(str(direccion_n))
        direccion_n=0
        cadena=""
   
    ".".join(lista) 
    print(f"DIRECCION IP ORIGEN",end="\t\t    ")
    print ('.'.join(lista) )


    for x in range (32,40):
            destino+=ip_hex[x]
    
    for x in range(0,8,2):
        cadena+=destino[x]
        cadena+=destino[x+1]
        destino_n=int(cadena,16)
        lista2.append(str(destino_n))
        destino_n=0
        cadena=""
  
    print(f"DIRECCION IP DESTINO",end="\t\t    ")
    print ('.'.join(lista2) )
    cad1=""
    cad1+=tipo
    cad1+=servicio
    cad2=""
    cad2+=longitud
    cad3=""
    cad3+=identificacion
    cad4=""
    cad4+=fragmentacion
    cad5=""
    cad5+=vida
    cad5+=protocolo
    cad6='0000'
    cad7=''
    cad7+=direccion[0]
    cad7+=direccion[1]
    cad7+=direccion[2]
    cad7+=direccion[3]
    cad8=""
    cad8+=direccion[4]
    cad8+=direccion[5]
    cad8+=direccion[6]
    cad8+=direccion[7]
    cad9=""
    cad9+=destino[0]
    cad9+=destino[1]
    cad9+=destino[2]
    cad9+=destino[3]
    cad10=""
    cad10+=destino[4]
    cad10+=destino[5]
    cad10+=destino[6]
    cad10+=destino[7]
    cad11='1'
    print(f"cad1  {cad1}")
    print(f"cad2  {cad2}")
    print(f"Longitud es {longitud}")
    print(f"cad3  {cad3}")
    print(f"cad4  {cad4}")
    print(f"cad5  {cad5}")
    suma1=int(cad1,16) + int(cad2,16)+int(cad3,16)+int(cad4,16)+ int(cad5,16)+int(cad11,16)
    suma2=int(cad6,16) + int(cad7,16)+int(cad8,16)+int(cad9,16)+ int(cad10,16)+int(cad11,16)
    suma3=suma1+suma2
    print(f"suma 1 resultado{suma1}")
    print(f"SUma dos {suma2}")
    print(f"suma tres{suma3}")

    resultado_bin=""
    resultado_bin_m=""
    complemento_a1=""
    resultado_bin=str(bin(suma3))
    
    for x in range(2,19):
        resultado_bin_m+=resultado_bin[x]
    for x in range(0,17):
        if resultado_bin_m[x]== '1':
            complemento_a1+="0"
        else:
            complemento_a1+="1"



    check=int(str(complemento_a1),2)
    check=check+1

    recorte=str(hex(check))
   
    recorte2=""
    recorte2+=recorte[2]
    recorte2+=recorte[3]
    recorte2+=recorte[4]
    recorte2+=recorte[5]
   
    ultimo=""
    ultimo=recorte2.upper()
    
    for x in range (20,24):
            checksum+=ip_hex[x]
    print(f"CHECKSUM                            {checksum}",end="\t    ")
    if ultimo == checksum:
        print(Fore.GREEN + ">>> Checksum Verificado <<<"+ Fore.LIGHTYELLOW_EX + " >{}<".format(ultimo) + Fore.RESET)
    else:
        print(Fore.RED +"Checksum incorrecto, datos alterados"+ Fore.RESET)

def texto():

    os.system('cls')
    
    print(Fore.RED + "\t\t\tEXAMINAR UN ARCHIVO DE TEXTO" + Fore.RESET)
    archivo_texto= open("tramaenhexdump.txt","r")
    texto=archivo_texto.read()
    archivo_texto.close()
    #split convierte la cadena de texto en una lista
    part=texto.split(' ')
    
    cabecera=""
    destino=""
    origen=""
    servicio=""
    ip_hex=""
    aux=""

    #agrega el coma a los pares (byets)
    for numero in range(2,16):
        cabecera+=part[numero]
  
    for numero in range(16,18):
        ip_hex+=part[numero]
  #la 19 es error  
    for numero in range(20,35):
        ip_hex+=part[numero]
#la divicion del 82
    for numero in range(35,36):
        aux+=part[numero]
    for numero in range(0,2):
        ip_hex+=aux[numero]
    for numero in range(37,39):
        ip_hex+=part[numero]
    #cabecera de ethernet
    for numero in range(2,8):
        destino+=part[numero]
    if destino[0]=="0":
        dirr=(Fore.LIGHTCYAN_EX +"       LA DIRECCIÓN ES INDIVIDUAL" + Fore.RESET)
    elif destino[0]=="1":
        dirr=(Fore.LIGHTCYAN_EX +"       LA DIRECCIÓN ES GRUPAL" + Fore.RESET)
    else:
        print("NO SE RECONOCE EL VALOR")

    for numero in range(8,14):
        origen+=part[numero]
        origen+=""
    for numero in range(14,16):
        servicio+=part[numero]
        servicio+=""
   # manera de hacer una cadena de caracteres
   #  ip_hex_numero=int(ip_hex)

    print(Fore.LIGHTWHITE_EX + "\n\t\t\t\tCABECERA DE ETHERNET" + Fore.RESET)
    print(f"\aDIRECCION MAC DESTINO               {acomodo(destino)}{dirr}")
    print(f"\aDIRECCION MAC DE ORIGEN             {acomodo(origen)}")
    print(f"\aTIPO DE SERVICIO                    {acomodo(servicio)}",end= "    ")
    # imprime el protocolo a usar
    if servicio == '0800':
        print(Fore.LIGHTCYAN_EX + "\t\t    INTERNET PROTOCOL VERSION 4")
    elif servicio == '0806':
        print(Fore.LIGHTCYAN_EX + "\t\t    ADDRESS RESOLUTION PROTOCOL" + Fore.LIGHTYELLOW_EX + " (ARP)" + Fore.RESET)
    elif servicio == '0842':
        print(Fore.LIGHTCYAN_EX + "\t\t    WAKE-ON-LAN")
    elif servicio == '22F3':
        print(Fore.LIGHTCYAN_EX + "\t\t    IETF TRILL PROTOCOL")
    elif servicio == '6003':
        print(Fore.LIGHTCYAN_EX + "\t\t    DECNET PHASE IV")
    elif servicio == '8035':
        print(Fore.LIGHTCYAN_EX + "\t\t    REVERSE ADRESS RESOLUTION PROTOCOL")
    elif servicio == '809B':
        print(Fore.LIGHTCYAN_EX + "\t\t    APPLETALK" + Fore.LIGHTYELLOW_EX + " (Ethertalk)" + Fore.RESET)
    elif servicio == '80F3':
        print(Fore.LIGHTCYAN_EX + "\t\t    APPLETALK ADRESS RESOLUTION PROTOCOL" + Fore.LIGHTYELLOW_EX + " (AARP)" + Fore.RESET)
    elif servicio == '8100':
        print(Fore.LIGHTCYAN_EX + "\t\t    VLAN-TAGGED FRAME AND SHORTEST PATH BRIDGING" + Fore.LIGHTYELLOW_EX + " (IEEE 802.1Q)" + Fore.RESET)
    elif servicio == '8137':
        print(Fore.LIGHTCYAN_EX + "\t\t    IPX")
    elif servicio == '8204':
        print(Fore.LIGHTCYAN_EX + "\t\t    QNX QNET")
    elif servicio == '86DD':
        print(Fore.LIGHTCYAN_EX + "\t\t    INTERNET PROTOCOL VERSION 6" + Fore.LIGHTYELLOW_EX + " (IPv6)" + Fore.RESET)
    elif servicio == '8808':
        print(Fore.LIGHTCYAN_EX + "\t\t    ETHERNET FLOW CONTROL")
    elif servicio == '8819':
        print(Fore.LIGHTCYAN_EX + "\t\t    COBRANET")
    elif servicio == '8847':
        print(Fore.LIGHTCYAN_EX + "\t\t    MPLS UNICAST")
    elif servicio == '8848':
        print(Fore.LIGHTCYAN_EX + "\t\t    MPLS MULTICAST")
    elif servicio == '8863':
        print(Fore.LIGHTCYAN_EX + "\t\t    PPPOE DISCOVERY STAGE")
    elif servicio == '8864':
        print(Fore.LIGHTCYAN_EX + "\t\t    PPPOE SESSION STAGE")
    elif servicio == '8870':
        print(Fore.LIGHTCYAN_EX + "\t\t    JUMBO FRAMES" + Fore.LIGHTYELLOW_EX + " (proposed)" + Fore.RESET)
    elif servicio == '887B':
        print(Fore.LIGHTCYAN_EX + "\t\t    HOMEPLUG 1.0 MME")
    elif servicio == '888E':
        print(Fore.LIGHTCYAN_EX + "\t\t    EAP OVER LAN" + Fore.LIGHTYELLOW_EX + " (IEEE 802.1X)" + Fore.RESET)
    elif servicio == '8892':
        print(Fore.LIGHTCYAN_EX + "\t\t    PROFINET PROTOCOL")
    elif servicio == '889A':
        print(Fore.LIGHTCYAN_EX + "\t\t    HYPERSCSI" + Fore.LIGHTYELLOW_EX + " (SCSI Over Ethernet)" + Fore.RESET)
    elif servicio == '88A2':
        print(Fore.LIGHTCYAN_EX + "\t\t    ATA OVER ETHERNET")
    elif servicio == '88A4':
        print(Fore.LIGHTCYAN_EX + "\t\t    ETHERCAT PROTOCOL")
    elif servicio == '88A8':
        print(Fore.LIGHTCYAN_EX + "\t\t    PROVIDER BRIDGING & SHORTEST PATH BRIDGING IEEE 802.1AQ")
    elif servicio == '88AB':
        print(Fore.LIGHTCYAN_EX + "\t\t    ETHERNET POWERLINK")
    elif servicio == '88CC':
        print(Fore.LIGHTCYAN_EX + "\t\t    LINK LAYER DISCOVERY PROTOCOL" + Fore.LIGHTYELLOW_EX + " (LLDP)" + Fore.RESET)
    elif servicio == '88CD':
        print(Fore.LIGHTCYAN_EX + "\t\t    SERCOS III")
    elif servicio == '88E1':
        print(Fore.LIGHTCYAN_EX + "\t\t    HOMEPLUG AV MME")
    elif servicio == '88E3':
        print(Fore.LIGHTCYAN_EX + "\t\t    MEDIA REDUNDANCY PROTOCOL" + Fore.LIGHTYELLOW_EX + " (IEC62439-2)" + Fore.RESET)
    elif servicio == '88E5':
        print(Fore.LIGHTCYAN_EX + "\t\t    MAC SECURITY" + Fore.LIGHTYELLOW_EX + " (IEEE 802.1AE)" + Fore.RESET)
    elif servicio == '88E7':
        print(Fore.LIGHTCYAN_EX + "\t\t    PROVIDER BACKBONE BRIDGES" + Fore.LIGHTYELLOW_EX + " (PBB)" + Fore.RESET)
    elif servicio == '88F7':
        print(Fore.LIGHTCYAN_EX + "\t\t    PRECISION TIME PROTOCOL OVER ETHERNET" + Fore.LIGHTYELLOW_EX + " (PTP)" + Fore.RESET)
    elif servicio == '8902':
        print(Fore.LIGHTCYAN_EX + "\t\t    CONNECTIVITY FAUL MANAGEMENT" + Fore.LIGHTYELLOW_EX + " (CFM)" + Fore.RESET)
    elif servicio == '8906':
        print(Fore.LIGHTCYAN_EX + "\t\t    FIBRE CHANNEL OVER ETHERNET" + Fore.LIGHTYELLOW_EX + " (FCoE)" + Fore.RESET)
    elif servicio == '8914':
        print(Fore.LIGHTCYAN_EX + "\t\t    FCOE INITIALIZATION PROTOCOL")
    elif servicio == '8915':
        print(Fore.LIGHTCYAN_EX + "\t\t    RDMA OVER CONVERGED ETHERNET" + Fore.LIGHTYELLOW_EX + " (RoCE)" + Fore.RESET)
    elif servicio == '891D':
        print(Fore.LIGHTCYAN_EX + "\t\t    TTETHERNET PROTOCOL CONTROL FRAME" + Fore.LIGHTYELLOW_EX + " (TTE)" + Fore.RESET)
    elif servicio == '892F':
        print(Fore.LIGHTCYAN_EX + "\t\t    HIGH-AVAILABILITY SEAMLESS REDUNDANCY" + Fore.LIGHTYELLOW_EX + " (HSR)" + Fore.RESET)
    elif servicio == '9000':
        print(Fore.LIGHTCYAN_EX + "\t\t    ETHERNET CONFIGURATION TESTING PROTOCOL")
    else: 
        print("El tipo de servicio a un no esta disponible ")
    ip(ip_hex)
    tcp(part)
    
    os.system('pause')

def red():
    print(Fore.RED + "SEGUIMOS EN DESARROLLO" + Fore.RESET)
    os.system('pause')
def lectura_txt():#Funcion 3 del menu del prograa
    archivo_texto= open("tramaenhexdump.txt","r")
    texto=archivo_texto.read()
    archivo_texto.close()
    print(Fore.RED + "\t\n\t\t    FLUJO DE DATOS" + Fore.LIGHTWHITE_EX)
    print(f"\n\n{texto}" + Fore.RESET)
def menu():
    while True:
        os.system('cls')
        print("°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°")
        print("°\t\t MENU                                     °")
        print("°  1. EXAMINAR ARCHIVO DE TEXTO  >LOCAL<                  °")
        print("°  2. EXAMINAR UN ARCHIVO DE TEXTO >WiFi<" + Fore.RED +" (PROXIMAMENTE)"+ Fore.RESET + "  °")
        print("°  3. FLUJO DE DATOS (HEXDUMP)                            °")
        print("°  4. " + Fore.RED +"SALIR DEL PROGRAMA"+ Fore.RESET + "                                  °")
        print("°                                                         °")
        print("°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°")
        opc = input("\n Ingrese una opcion: ")
         #Validacion del menu
        try:
            opc = int(opc)
            os.system('cls')
        except ValueError:
           print ("La entrada es incorrecta: escribe un numero entero")
           os.system('pause')
        if opc == 1:
            texto()
        elif opc == 2:
            red()
        elif opc == 3:
            lectura_txt()
            os.system("pause")
        elif opc ==4:
            print(Fore.RED + "\tSALIENDO DEL PROGRAMA"+ Fore.RESET)
            input("\tPRESIONA CUALQUIER TECLA")
            os.system('cls')
            print("**********\n          *\n          *\n   ********\n          *\n          *\n**********")
            time.sleep(1)
            os.system('cls')
            print("\n ******** \n*        *\n        *\n       *\n      *\n     *\n   *\n *       *\n********")
            time.sleep(1)
            os.system('cls')
            print("    *\n   **\n  * *\n *  *\n    *\n    *\n    *\n    *\n*********")
            time.sleep(1)
            os.system('cls')
            break
menu()
