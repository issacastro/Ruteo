// Castro Mejia Angel Issac 2016300265
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

char TS[50],OP_CLASS[50],OP_COPIA[50],OP_NUM[50],OP[50];
char TD[50],TP[50],FRAC[60],P[50]="/sbin/ifconfig ";
struct in_addr in;
struct sockaddr_in fuente,destino;
struct IPStruct {
        __u8 Hlen:4,Version:4;
        __u8 BMI:3,TS1:1,TS2:1,TS3:1,NoUsado:2;
      	__u16 Tlen;
      	__u16 IDatagrama;
       	__u16 B1:1,B2:1,B3:1,Desplazamiento:13;
       	__u8 Tvida;
       	__u8 Protocolo;
       	__u16 SumaV;
        __u32 DSource;
        __u32 DDest;
        __u8 Tcopy:1,Tclass:2,Tnum:5;
};
 
int noIPv4=0,IPv4=0,ICMPv4=0,IGMP=0,IP=0,TCP=0,UDP=0,IPv6=0,OSPF=0;
int Fbyte=0,Lbyte=0;
int analizar(int b,char buffer[65536]){

struct ethhdr *eth = (struct ethhdr *)buffer;
struct IPStruct *ip= (struct IPStruct*)(buffer + sizeof(struct ethhdr));

if((unsigned int)ip->Version!=4){
noIPv4+=1;
return 0;
}
else{
	IPv4+=1;
	memset(&fuente, 0, sizeof(fuente));
    fuente.sin_addr.s_addr = ip->DSource;
	memset(&destino, 0, sizeof(destino));
    destino.sin_addr.s_addr = ip->DDest;
//Protocolo de Capa superior
switch(ip->Protocolo){
	case 0x01:
	ICMPv4+=1;
	strcpy(TP,"ICMPv4");
	break;
	case 0X02:
	IGMP+=1;
	strcpy(TP,"IGMP");
	break;
	case 0x04:
	IP+=1;
    strcpy(TP,"IP");
	break;
	case 0x06:
	TCP+=1;
	strcpy(TP,"TCP");
	break;
	case 0x11:
	UDP+=1;
	strcpy(TP,"UDP");
	break;
	case 0x29:
	IPv6+=1;
	strcpy(TP,"IPv6");
	break;
    case 0x59:
	OSPF+=1;
	strcpy(TP,"OSPF");
	break;
  	default:
  	strcpy(TP,"Otro Protocolo");				
  	break;
}

//Tipo de Servicio
	if ((unsigned int)ip->TS1==0 && (unsigned int)ip->TS2==0 && (unsigned int)ip->TS3==0) {
		strcpy(TS,"Precedencia(XXX000)");
		}
		else {
  			if ((unsigned int)ip->TS3==0) {
     			strcpy(TS,"Diferenciado Intertnet (XXXXX0)");
  			 }
  			  else{
    				if ((unsigned int)ip->TS2==1) {
      					strcpy(TS,"Dferenciado Local (XXXX11)");
    					} 
					else {
      						strcpy(TS,"Diferenciado Temporal o Experimental (XXXX01)");
					}
				}
			}
// Fragmentacion
			if ((unsigned int)ip->B2==0) {
      				strcpy(FRAC,"No Fragmentado");
    			}
			if ((unsigned int)ip->B2==1) {
      				strcpy(FRAC,"No Fragmentar");
    			}
    			else {
        			if ((unsigned int)ip->Desplazamiento==0 && (unsigned int)ip->B3 ==0 ) {
          				(FRAC,"Sin fragmentaciòn");
        			} 
				else {
            				if ((unsigned int)ip->Desplazamiento==0 && (unsigned int)ip->B3 ==1) {
                				strcpy(FRAC, "Primer fragmento");
              				}
            				if ((unsigned int)ip->Desplazamiento!=0 && (unsigned int)ip->B3 ==1) {
                				strcpy(FRAC, "Fragmento intermedio");
            				}
            				if ((unsigned int)ip->Desplazamiento!=0 && (unsigned int)ip->B3 ==0) {
                				strcpy(FRAC, "Ultimo fragmento");
            				}
        			}
			}
//Primer y Ultimo Byte
Fbyte=(unsigned int)ip->Desplazamiento *8*4;	
Lbyte=Fbyte+ntohs(ip->Tlen)-(((unsigned int)(ip->Hlen))*4)-1;

//Opciones de Datagrama
if ((((unsigned int)(ip->Hlen))*4) ==20) {
      				strcpy(OP, "Datagrama sin opciones" );
    			} 
			else {
      				strcpy(OP,"Datagrama con opciones");
       				if ((unsigned int)ip->Tcopy ==0) {
         				strcpy(OP_COPIA, "En el primer fragmento");
      				} 
				else {
         				strcpy(OP_COPIA, "Todos los fragmentos");
       				}
				switch ((unsigned int)ip->Tclass) {
         				case  0:
            					strcpy(OP_CLASS,"control de datagrama");
            					break;
         				case 1:
            					strcpy(OP_CLASS, "Reservado");
            					break;
         				case 2:
            					strcpy(OP_CLASS, "Depuracion y mantenimiento");
            					break;
         				case 3:
            					strcpy(OP_CLASS, "Reservado");
            					break;
       				}
				switch ((unsigned int)ip->Tnum) {
         				case 0:
         					strcpy(OP_NUM, "Fin de opción");
         					break;
         				case 1:
         					strcpy(OP_NUM, "No operación");
         					break;
         				case 3:
         					strcpy(OP_NUM, "Ruta de origen suelta");
         					break;
         				case 4:
         					strcpy(OP_NUM, "Estampa de tiempo");
         					break;
         				case 7:
         					strcpy(OP_NUM, "Registro de ruta");
         					break;
         				case 9:
         					strcpy(OP_NUM, "Ruta de origen estricta");
         					break;
       				}

}
			
}

return 1;
}

void escribir(int b, char buffer[65536],int i, int paq){
struct IPStruct *ip= (struct IPStruct*)(buffer + sizeof(struct ethhdr));
    FILE* arch;
	struct ethhdr *eth = (struct ethhdr *)buffer;
    arch = fopen("Temporal.txt", "a+");
    fprintf(arch,"\nDatagrama %i ",i+1);
    fprintf(arch, "\n");
    fprintf(arch,"Analisis de Datagrama \n");
    fprintf(arch,"   |-Direccion de Origen    : %s \n",inet_ntoa(fuente.sin_addr) );
    fprintf(arch,"   |-Direccion de Destino   : %s \n",inet_ntoa(destino.sin_addr));
	fprintf(arch,"   |-Longitud de Cabezara   : %d Bytes\n",((unsigned int)(ip->Hlen))*4);
	fprintf(arch,"   |-Longitud de Total      : %d Bytes\n",ntohs(ip->Tlen));
	fprintf(arch,"   |-ID Datagrama           : %d \n",ntohs(ip->IDatagrama));
	fprintf(arch,"   |-Tiempo de Vida         : %d \n",(unsigned int)ip->Tvida);
	fprintf(arch,"   |-Protocolo de Capa Sup  : %s \n",TP);
	fprintf(arch,"   |-Longitud Carga Util    : %d \n",ntohs(ip->Tlen)-(((unsigned int)(ip->Hlen))*4));
	fprintf(arch,"   |-Tipo de Servicio       : %s \n",TS);
	fprintf(arch,"   |-Fragmentacion          : %s \n",FRAC);
	fprintf(arch,"   |-Primer Byte            : %d \n",Fbyte);
	fprintf(arch,"   |-Ultimo Byte            : %d \n",Lbyte);
	fprintf(arch,"   |-Opciones               : %s \n",OP);
if ((((unsigned int)(ip->Hlen))*4) !=20) {
    fprintf(arch,"   |-Copia                  : %s \n",OP_COPIA); 	
	fprintf(arch,"   |-Clase                  : %s \n",OP_CLASS);
	fprintf(arch,"   |-Numero                 : %s \n",OP_NUM);			
    			}
	fprintf(arch,"----------------------------------------------------------\n");
	
	fclose(arch);
	if(i==paq-1){
		FILE* arch1;
		char cadena[256];
		arch = fopen("Temporal.txt", "r");
		arch1 = fopen("Reporte.txt", "w+");
	fprintf(arch1,"----------------------------------------------------------\n");
	fprintf(arch1,"\t\t\t\t\tReporte de Datagramas\n");
	fprintf(arch1,"----------------------------------------------------------\n");
    fprintf(arch1,"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	fprintf(arch1,"Total de Paquetes Capturados    :%d \n",paq);
	fprintf(arch1,"Total de Paquetes No Analizados :%d \n",noIPv4);
	fprintf(arch1,"    |-ICMPv4 :%d \n",ICMPv4);
	fprintf(arch1,"    |-IGMP   :%d \n",IGMP);
	fprintf(arch1,"    |-IP     :%d \n",IP);
	fprintf(arch1,"    |-TCP    :%d \n",TCP);
	fprintf(arch1,"    |-UDP    :%d \n",UDP);
	fprintf(arch1,"    |-IPv6   :%d \n",IPv6);
	fprintf(arch1,"    |-OSPF   :%d \n",OSPF);
    fprintf(arch1,"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		while (fgets(cadena, 256, arch)!= NULL)
	{
		fprintf(arch1,"%s",cadena);
	}
	fclose(arch1);
	fclose(arch);
	} 
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
	remove("Temporal.txt");
	}
	
	 //Cerrando el Socket y quitando modo Promiscuo
	 strcat(P,red);
	 strcat(P," -promisc");
	 system(P);
     close(s);
	  printf("\nModo Promiscuo Desactivado...\n");
	  return 0;
}