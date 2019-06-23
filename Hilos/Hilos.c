#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
 
struct param{
 char *frase;
 int numero;
};
/*
 * Función que ejecutarán los hilos.
 */
void hiloMensaje(struct param *mensa){
 printf("%s %d\n",mensa->frase, mensa->numero);
}
 
int main() {
 pthread_t thd1, thd2;
 struct param param1 = {"Soy el hilo: ",1};
 struct param param2 = {"Digo otra cosa ",2};
 /*
  * Creamos dos hilos
  */
 /* La función la pasaremos como (void*)nombreFuncion.
  * Es decir, hacemos un CAST a void*.
  * También es importante realizar esto con la dirección de memorio
  * de la variable que contiene los parámetros.
  */
 pthread_create (&thd1, NULL, (void*)hiloMensaje, (void*)&param1);
 pthread_create (&thd2, NULL, (void*)hiloMensaje, (void*)&param2);
  
 /*
  * Esperamos la finalización de los hilos
  */
 pthread_join(thd1, NULL);
 pthread_join(thd2, NULL);
  
 printf("Han finalizado los thread.\n");
}
