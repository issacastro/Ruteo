// CASTRO MEJIA ANGEL ISSAC 2016300265
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <arpa/inet.h>


#define LENHW 6
#define LENPROTOCOLO 4

char red[10];
int conta=0;
int total_ip;
pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;

typedef struct hilos_ARP {
    int id;
    int contador;
    unsigned char ipDest[16];
    struct hilos_ARP * next;
    struct hilos_ARP * prev;
}ARPHilo;

typedef struct _ARP {

    unsigned char destinoEthernet[6];       /*Dirección de difusión 0xFF*/

    unsigned char origenEthernet[6];        /*Dirección MAC del transmisor*/

    unsigned short tipoEthernet;            /*Tipo de mensaje en la trama Ethernet*/

    unsigned short tipoHardware;            /*Tipo de hardware utilizado para difundir el mensaje ARP (Ethernet) */

    unsigned short tipoProtocolo;           /*Tipo de protocolo de red utilizado para difundir el mensaje ARP (IP) */

    unsigned char longitudHardware;         /*Tamaño de direcciones de hardware (6 bytes) */

    unsigned char longitudProtocolo;        /*Tamaño de direcciones del protocolo (4 bytes) */

    unsigned short tipoMensaje;             /* Solicitud o respuesta*/

    unsigned char origenMAC[LENHW];             /*Dirección MAC del transmisor*/

    unsigned char origenIP[LENPROTOCOLO];              /*Dirección IP del transmisor*/

    unsigned char destinoMAC[LENHW];            /*Dirección MAC del receptor (dirección solicitada) */

    unsigned char destinoIP[LENPROTOCOLO];             /*Dirección IP del receptor (dato de entrada) */

} ARP;

void escribir(ARP respARP){
FILE* arch;
arch = fopen("Direcciones.txt", "a+");
    fprintf(arch,"\n Dirección IP: ");
    for(int i=0; i < LENPROTOCOLO; i++) {
    fprintf(arch,"%d",respARP.origenIP[i]);
    if(i<LENPROTOCOLO-1) fprintf(arch,".");
    }
    fprintf(arch,"\n Dirección MAC: ");
    for(int i=0; i < LENHW; i++){ 
    fprintf(arch,"%02x",respARP.origenMAC[i]);
    if(i<LENHW-1) fprintf(arch,":");
    }
    fprintf(arch,"\n");
    fclose(arch);
}

void *proceso_arp(void *_data) {
    ARPHilo *data = (ARPHilo *) _data;
    int idThread = data->id;
    //printf("\nID: %d\n",idThread);
    char *ip_dest = (char *) malloc(sizeof(char));
    strcpy(ip_dest, (const char *) data->ipDest);

    struct ifreq ethreq;
    int optval;

    ARP buffer;
    unsigned char mac_address[LENHW] = {0};
    unsigned char ip_address[LENHW] = {0};

    unsigned char destinoIP[LENPROTOCOLO];
    char clase[3] = {0};
    int position = 0;
    int length = 3;
    int counter = 0;


    for (int j = 0; j <= strlen(ip_dest); ++j) {
        if (ip_dest[j] == '.' || ip_dest[j] == '\0') {
            length = j - position;
            bzero(clase, 3);
            strncpy(clase, &ip_dest[position], length);
            destinoIP[counter] = (unsigned char) atoi(clase);
            position = j + 1;
            counter++;
        }
    }

    memset(&ethreq, 0, sizeof(struct ifreq));

    //Abrir un Socket

    int socket_packet;
    if ((socket_packet = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
        printf("ERROR: No se pudo abrir el socket, %d\n", socket_packet);
        exit(1);
    }

    //Configuracion del socket para difusion
    setsockopt(socket_packet, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));

    //Establecer el dispositivo a utilizar.

    strncpy(ethreq.ifr_name, red, IFNAMSIZ);

    //Obtener la configuración de las banderas.
    // Obtener las banderas actuales que el dispositivo pueda tener
    if (ioctl(socket_packet, SIOCGIFFLAGS, &ethreq) == -1) {
        perror("Error: No se pudieron obtener las banderas del dispositivo ");
        exit(1);
    }


    if (ioctl(socket_packet, SIOCGIFADDR, &ethreq) != 0) {
        perror("Error: No se puede obtener la direccion MAC");
        exit(1);
    }

    memcpy(ip_address, ethreq.ifr_addr.sa_data, LENHW);

    if (ioctl(socket_packet, SIOCGIFHWADDR, &ethreq) != 0) {
        perror("Error: No se puede obtener la direccion MAC");
        exit(1);
    }

    memcpy(mac_address, ethreq.ifr_hwaddr.sa_data, LENHW);

    //Envio Mensaje de Solicitud ARP

    ARP msgARP;

    for (int i = 0; i < LENHW; i++) msgARP.destinoEthernet[i] = 0xFF;

    for (int i = 0; i < LENHW; i++) msgARP.origenEthernet[i] = mac_address[i];

    msgARP.tipoEthernet = htons(ETH_P_ARP);

    msgARP.tipoHardware = htons(ARPHRD_ETHER);

    msgARP.tipoProtocolo = htons(ETH_P_IP);

    msgARP.longitudHardware = LENHW;

    msgARP.longitudProtocolo = LENPROTOCOLO;

    msgARP.tipoMensaje = htons(ARPOP_REQUEST);

    for (int i = 0; i < LENHW; i++) msgARP.origenMAC[i] = mac_address[i];

    for (int i = 0; i < LENPROTOCOLO; i++) msgARP.origenIP[i] = ip_address[i + 2];

    for (int i = 0; i < LENHW; i++) msgARP.destinoMAC[i] = 0x00;

    for (int i = 0; i < LENPROTOCOLO; i++) msgARP.destinoIP[i] = destinoIP[i];

    // Definir la interface de red para el parametro de sendto
    struct sockaddr addr;
    strncpy(addr.sa_data, red, sizeof(addr.sa_data));
    ssize_t bytesSent;

    //Variables de respuesta arp
    ARP respARP;
    ssize_t bytesReceived = 0;
    int correct; //Valida que el mensaje ARP de respuesta sea el indicado para este hilo.
    data->contador=0;
    do {

        data->contador++;
        bytesSent = sendto(socket_packet, &msgARP, 42, 0, &addr, sizeof(addr));

        if (bytesSent <= 0) {
            perror("sendto() falló");
            exit(EXIT_FAILURE);
        }

        pthread_mutex_lock(&mutex_print);
        if (data->contador>4) {
          printf("\n\nTiempo Excedido para: ");
          for (int i = 0; i < LENPROTOCOLO; i++) printf("%d ", destinoIP[i]);
          printf("\n");
          pthread_mutex_unlock(&mutex_print);
          close(socket_packet);
          pthread_exit(&idThread);
        } else {
          printf("\n\nMandando Solicitud ARP");
          printf("\n");
          
        }
        pthread_mutex_unlock(&mutex_print);

        do {


            //Recibo Mensaje de Respuesta ARP
            bytesReceived = recvfrom(socket_packet, &buffer, 42, 0, NULL, NULL);

            respARP = buffer;
        } while (htons(respARP.tipoMensaje) == 1);

        correct = 1;
        for (int j = 0; j < LENPROTOCOLO; ++j) {
            if (respARP.origenIP[j] != destinoIP[j]){
                correct = 0;
                break;
            }
        }

    } while (!correct);

    pthread_mutex_lock(&mutex_print);
    printf("Recibiendo Respuesta:");
    for(int i=0; i < LENPROTOCOLO; i++) printf("%d ",respARP.origenIP[i]);
    printf("\n");
    escribir(respARP);
    pthread_mutex_unlock(&mutex_print);

    close(socket_packet);

    pthread_exit(&idThread);
}

ARPHilo * LISTAIP(int id, char * ipDest, ARPHilo * ultima){
    ARPHilo * new = (ARPHilo*)malloc(sizeof(ARPHilo));
    new->id = id;
    strcpy((char *) new->ipDest, ipDest);
    if (ultima == NULL && id == (total_ip-1)){
        new->next = new;
        return new;
    } else if (ultima == NULL){
        new->next = NULL;
        new->prev = NULL;
        return new;
    } else if (id == (total_ip-1)){
        ARPHilo * head = ultima;
        while (head->prev != NULL) head = head->prev;
        new->next = head;
    }
    new->prev = ultima;
    ultima->next = new;
    ultima = ultima->next;

    return ultima;
}

int main() {
    int error = 0;
    int * salida;
    ARPHilo * data = NULL;
    
    system("clear");
	printf("Introduce la interfaz de red:");
	scanf("%s",&red);
    printf("Introduce Numero de IPS:");
	scanf("%d",&total_ip);

    char ip_dest[total_ip][16];

    for (int i = 0; i < total_ip; ++i) {

        bzero(ip_dest[i],16);
        printf("\nIngresa la dirección de destino %d: ", i+1);
        scanf("%s", ip_dest[i]);

    }

    pthread_t hilos[total_ip];
    for (int i = 0; i < total_ip; ++i) {
        data = LISTAIP(i,ip_dest[i],data);
    }

    for (int j = 0; j < total_ip; ++j) {
        data = data->next;
        //Crear Hilos
        error = pthread_create(&hilos[j], NULL, proceso_arp, data);
        if (error){
            fprintf(stderr,"Error: %d: %s\n",error,strerror(error));
            exit(-1);
        }
    }

    for (int k = 0; k < total_ip; ++k) {
        //Esperando Hilos
        error = pthread_join(hilos[k],(void**)&salida);
        if (error){
            fprintf(stderr,"Error %d: %s\n",error,strerror(error));
        }
    }
    printf("\n");
    return 0;
}
