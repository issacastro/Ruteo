#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

char TD[50],TP[50],P[50]="/sbin/ifconfig ";
int IEEE=0,ETER=0,IPv4=0,IPv6=0,ARP=0, CFE=0,SMAC=0,Payload;
int analizar(int b,char buffer[65536]){

struct ethhdr *eth = (struct ethhdr *)buffer;
if(htons(eth->h_proto) <=0x05DC){
IEEE+=1;
return 0;
}
else{
	ETER+=1;
if(eth->h_dest[0]%2==0){
strcpy(TD,"Unicast");
}else if(eth->h_dest[0]==255){strcpy(TD,"Broadcast");}
else{strcpy(TD,"Multicast");}

switch(htons(eth->h_proto)){
	case 0x0800:
	IPv4+=1;
	Payload=b-34;
	strcpy(TP,"IPv4");
	break;
	case 0x86DD:
	IPv6+=1;
	Payload=b-54;
	strcpy(TP,"IPv6");
	break;
	case 0x0806:
	ARP+=1;
	Payload=b-42;
	strcpy(TP,"ARP");
	break;
	case 0x8808:
	CFE+=1;
	Payload=b-18;
	strcpy(TP,"Control de Flujo Ethernet");
	break;
	case 0x88E5:
	SMAC+=1;
	Payload=b-46;
	strcpy(TP,"Seguridad M.A.C");
	break;

}
}
return 1;
}

void escribir(int b, char buffer[65536],int i, int paq){
    FILE* arch;
	struct ethhdr *eth = (struct ethhdr *)buffer;
    arch = fopen("Tramas.txt", "a+");
	if(i==0){
	fprintf(arch,"----------------------------------------------------------\n");
	fprintf(arch,"\t\t\t\t\tINICIO DEL ARCHIVO\n");
	fprintf(arch,"----------------------------------------------------------");
	}
    fprintf(arch,"\nTrama %i ",i+1);
    fprintf(arch, "\n");
    fprintf(arch,"Analisis de la Trama Ethernet II \n");
    fprintf(arch,"   |-Direccion de Origen    : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(arch,"   |-Direccion de Destino   : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(arch,"   |-Tipo de Protocolo      : %s \n",TP);
	fprintf(arch,"   |-Longitud de Trama      : %d \n",b);
	fprintf(arch,"   |-Carga Util de Trama    : %d \n",Payload);
	fprintf(arch,"   |-Tipo de Difusion       : %s \n",TD);
	fprintf(arch,"----------------------------------------------------------\n");
	if(i==paq-1){
    fprintf(arch,"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	fprintf(arch,"Total de Paquetes Capturados :%d \n",paq);
	fprintf(arch,"    |-IEEE 802.3 :%d \n",IEEE);
	fprintf(arch,"    |-Ethernet II:%d \n",ETER);
    fprintf(arch,"            ->IPv4  :%d \n",IPv4);
	fprintf(arch,"            ->IPv6  :%d \n",IPv6);
	fprintf(arch,"            ->ARP   :%d \n",ARP);
	fprintf(arch,"            ->C.F.E :%d \n",CFE);
	fprintf(arch,"            ->S.MAC :%d \n",SMAC);	
	fprintf(arch,"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	fprintf(arch,"\t\t\t\t\tFINAL DEL ARCHIVO\n");
	fprintf(arch,"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n\n");
	}
	fclose(arch);     
	 
}
int main(){
	//Variables
	char buffer[65536],red[10];
	int paq,s,addrlen,b;
	struct  ifreq ethreq;
	struct sockaddr saddr;
	system("clear");
	printf("Introduce la interfaz de red:");
	scanf("%s",&red);

	printf("Introduce Numero de Paquetes:");
	scanf("%d",&paq);

	strcpy(ethreq.ifr_name,red);
	//Abriendo socket
	
    s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    	if(s==-1){
		perror("Error al abrir el socket");
	}else{
         perror("Exito al abrir el socket");
    strncpy (ethreq.ifr_name, red,  IFNAMSIZ);  
    ioctl  (s,  SIOCGIFFLAGS,  &ethreq);  
	ethreq.ifr_flags |=  IFF_PROMISC;  
    ioctl  (s,  SIOCSIFFLAGS,  &ethreq);
	printf("\nModo Promiscuo Activado...\n"); 
	addrlen= sizeof(saddr);

	//Capturador de Tramas
	for(int i=0;i<paq;i++){
	b=recvfrom(s,buffer,sizeof(buffer),0,&saddr,&addrlen);
	if (b == -1) {
      perror("Recvfrom fallo");
      return -1;
   }
   else{
   if(analizar(b,buffer))
   escribir(b,buffer,i,paq);
   }
	}
	printf("Proceso completado");
	}
	
	 //Cerrando el Socket y quitando modo Promiscuo
	 strcat(P,red);
	 strcat(P," -promisc");
	 system(P);
     close(s);
	  printf("\nModo Promiscuo Desactivado...\n");
	  return 0;
}