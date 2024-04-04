from scapy.all import *

def procesar_paquete(paquete):
    print(paquete.summary())  # Imprime un resumen del paquete capturado

# Inicia la captura de paquetes
sniff(prn=procesar_paquete, filter="tcp")  # Filtra solo paquetes TCP, puedes ajustarlo según tus necesidades