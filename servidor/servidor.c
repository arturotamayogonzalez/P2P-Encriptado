/*
    Servidor central
    Este servidor debe ejecutarse antes que cualquier archivo peer.c.
    EL servidor maneja las peticiones de conectar, publicar y busqueda provenientes de un peer
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h> // para sockaddr_in
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <sys/time.h>
#include <stdbool.h>

#define CONEXIONES 100
#define PEERSMAXIMOS 100
#define BUFFERMAXIMO 512
#define NOMBREARCHIVOMAXIMO 100
#define TAMAÑOSTRING 100
#define PULSO 15
#define CONECTAR 1
#define PUBLICAR 2
#define DESCARGAR 3

/*RSA*/

//Algoritmo de exponenciacion modular
int AEM(int p, int e, int n){
 
  long r2 = 1;
  long r1 = 0;
  long Q = 0;
  long R = 0;
 
  while( e != 0 ){
     R = (e % 2);
     Q = ((e - R) / 2);
 
     r1 = ((p * p) % n);
 
       if(R == 1){
          r2 = ((r2 * p) % n);
       }
     p = r1;
     e = Q;
  }
return r2;
}

void encriptar(int e, int n, char* sesion, char* id){
    
    FILE *sesiones;
    sesiones = fopen("sesiones.txt", "a");
    fclose(sesiones);
    
    
    FILE *llave;
    llave = fopen("llave.txt", "w+");
    fprintf(llave, "%s", sesion);
    fclose(llave);

    llave = fopen("llave.txt", "r+");
    sesiones = fopen("sesiones.txt", "w+");

    char ch;
    int valor;

    fprintf(sesiones, "\nId Peer: \n\t%s\n", id);
    fprintf(sesiones, "Llave de sesion: \n\t");
    while (1) {
        ch = getc(llave);
        if (ch == -1){
            break;
        }
        valor = AEM(ch, e, n);
        fprintf(sesiones, "%ld ", valor);
    }

    fclose(sesiones);
    fclose(llave);
}

/*******************[ESTRUCTURAS]**********************************/

//Estructura para el servidor
typedef struct socket_servidor {

    int descriptor_socket; //Descriptor del socket
    int puerto; //Puerto al que sera asignado
    char ip[TAMAÑOSTRING]; //ip del servidor
    char llavesesion[TAMAÑOSTRING];
}socket_servidor;

//Estructura para la informacion de los archivos
typedef struct informacion_archivo_publicado
{
    char nombre_archivo[NOMBREARCHIVOMAXIMO]; //Nombre del archivo
    char ip[TAMAÑOSTRING]; //Ip del peer que publicó
    char id[TAMAÑOSTRING]; //Identificador del peer que publicó
    int puerto; //Puerto del peer que publicó
    
}informacion_archivo_publicado;

/*
    Estructura para unir peers
*/

//Estructura para la información del peer
typedef struct informacion_peer
{
    char id[TAMAÑOSTRING]; //Id del peer
    char ip[TAMAÑOSTRING]; //Ip del peer
    int puerto; //Puerto del peer al que fue asignado
    unsigned long long ultimo_ping; //Tiempo de ping se le dio al peer
    int ku1; //Llave publica primer elemento
    int ku2; //Llave publica segundo elemento
}informacion_peer;

//Estrucutra para saber que peers estan conectados al servidor
typedef struct peer_conectado
{
    informacion_peer *lista_peers[2]; //Estructura del tipo informacion del peer
    int contador_peers; //Contador de peers
}peer_conectado;

/****************[CONSTANTES]*******************************/

char *carpeta_por_defecto="p2p-servidor"; //Carpeta del servidor donde almacenara la bd con toda la información
char *bd_archivos_publicados="archivos_publicados.db"; //Nombre de la bd
peer_conectado *peers_conectados; //Apuntador a estructura para obtener la informacion de los peers conectados al servidor
char ip_servidor[TAMAÑOSTRING]; //asignacion de espacio para ip del servidor
int puerto_servidor; //Puerto del servidor al que va a ser asignado
char llavesesion[TAMAÑOSTRING];

/******************[DECLARACIÓN DE METODOS]****************************/

int iniciarServidor(int puerto); //Iniciar el servidor
socket_servidor obtenerSocketServidorTcp(int puerto); //Obtener socket TCP
void *hiloEsperaConexion(void *arg_sfd); //Crear hilo para esperar una conexion del peer
void *hiloDeProcesoPeer(void *param); //Crear un hilo por casa proceso peer

void solicitudDeConexion(int sfd,char *datos); //Manejar la solicitud de conexion
int agregarPeerALista(informacion_peer *peer); //Agregar peer conectado a la lista de peer´s conectados
int peerVivo(char *id); //Saber si un peer aun esta conectado
informacion_peer* obtenerInformacionPeerVivo(char *id); //Obtener informacion de un peer conectado

void solicitudDePublicacion(int sfd,char *datos); //Manejar la solicitud de publicar un archivo al servidor
int guardarArchivoPublicado(informacion_archivo_publicado archivo_peer); //Guardar el archivo publicado
 
void solicitudDeDescarga(int sfd,char *datos); //Manejar la solicutd de descarga de un archivo

void mostrarArchivosPublicados(void); //Mostrar todas los archivos publicados
void mostrarPeersConectados(void); //Mostrar todos los peers conectados

void menu(void); //Menu para ejecutar una accion despues de la seleccion de una accion
void menu_acciones(void); //Menu de opciones


/*********************[METODOS EN COMUN CON LOS PEERS]**************************/
/*
    Borrar el flujo de entrada o las subpartes que se van mandando
    parametro:
        datos y tamaño del arreglo
*/
void limpiarDatos(char *datos,int tamaño)
{
    fflush(stdout);
    memset(datos, 0, tamaño);
}

/*
    Generar identificador único global para cada peer a partir de cuanto duro su ejecucion
        regreso: ID único global
*/
char *obtenerIDUnico()
{
    char *id=(char *)malloc(sizeof(char)*100); //Reservar memoria para un id
    struct timeval tiempo; //Estructura del tipo tiempo
    gettimeofday(&tiempo, NULL); //Obtener el tiempo actual
    unsigned long long milisegundos =(unsigned long long)(tiempo.tv_sec) * 1000 +(unsigned long long)(tiempo.tv_usec) / 1000; //Asignacion de un identificador unico
    //tv_sec = segundos, tv_usec = milisegundos
    sprintf(id,"%llu",milisegundos); //Guardamos el id
    return id; //regresar el Id
}

/* *********************** [METODOS] ************************************** */

/*
    Inicia el servidor.
    parametro:
        número de puerto en el que se debe iniciar el servidor
    regreso
        -1 si falló el escriptor de socket
*/
int iniciarServidor(int puerto)
{
    int *socketServidor=(int *)malloc(sizeof(int)); //Guardar memoria para la variable sfd en donde guardaremos la informacion del socket servidor
    int nsfd; //Declaracion de variables
    int sin_size=sizeof(struct sockaddr_in);
    char datos[BUFFERMAXIMO]; //Definicion de la cantidad de datos
    struct sockaddr_in from_addr; //Declaramos una estructura de este tipo para poder acceder a elementos de un socket

    socket_servidor servidor_socket; //socket_servidor proporciona un socket de tipo TCP, declaramos uno
    servidor_socket=obtenerSocketServidorTcp(puerto); //creamos el socket que acabmos de declarar con la funcion obtenerSocketServidorTcp y el puerto al que se desea asignar
    puerto=servidor_socket.puerto; //Le asignamos el puerto
    *socketServidor=servidor_socket.descriptor_socket; //Guardamos la informaciñon del socket creado

    if(socketServidor<0) //Si la accion no fue exitosa regresa un -1
        return -1;

    puerto_servidor=puerto; //Recupera el número de puerto del servidor, al que se envió la solicitud.
    printf("El servidor se inició en IP %s Puerto %d.\n",ip_servidor,puerto_servidor); //Imprimimos a donde fue conectado el servidor
    pthread_t hilo_servidor; //Declaramos un nuevo hilo para el servidor
    pthread_create(&hilo_servidor, NULL, hiloEsperaConexion, socketServidor); //Creamos el hilo anteriormente declarado
    return *socketServidor; //regresamos el hilo servidor
}

/*
    Subproceso del servidor que esperará a que otros pares se conecten.
    Parametro:
        descriptor de socket del servidor.
    regreso
        Puntero nulo;
*/
void *hiloEsperaConexion(void *arg_sfd)
{
    struct sockaddr_in from_addr; //Declaramos una estructura de este tipo para poder acceder a elementos de un socket
    int sfd,nsfd;
    int sin_size=sizeof(struct sockaddr_in);
    sfd=*(int *)arg_sfd; //Asignamos el hilo que ingreso a una variable
    while((nsfd=accept(sfd,(struct sockaddr*)&from_addr,&sin_size))!=-1) //Se llama a la función accept( ) que sirve para estar a la escucha y permitir que algún cliente se conecte
    {
        //printf("Peer conectado...\n");
        pthread_t servidorhilo_id; //Declaramos un hilo
        pthread_create(&servidorhilo_id, NULL, hiloDeProcesoPeer, &nsfd); //Lo creamos con el socket que acaba de conectarse
    }
    printf("Servidor DETENIDO. Reinicie la aplicación.\n"); //Caso sontrario el servidor no recibio la conexion
    close(sfd);
    return NULL;
}
/*
    Crear socket TCP
    parametro:
        número de puerto
    regreso
        socket
*/
socket_servidor obtenerSocketServidorTcp(int puerto)
{
    struct sockaddr_in mi_direccion; //Se declaran una estructura del tipo socket
    int sockettcp=0,nsfd;
    socket_servidor servidor_socket; //socket_servidor proporciona un socket de tipo TCP, declaramos uno
    servidor_socket.puerto=puerto; //Se le asigna el puerto que fue ingresado en la función
    servidor_socket.descriptor_socket=0; //Limpiamos toda su información

    sockettcp=socket(PF_INET,SOCK_STREAM,0); //Se llama a la función socket en donde crea un socket sin nombre de un dominio, tipo y protocolo específico en este caso PF_INET es el dominio. Con SOCK_STREAM especificaremos que la conexión será TCP y con 0 un protocolo por defecto.
    mi_direccion.sin_family=AF_INET; //Asignación del protocolo
    mi_direccion.sin_port=htons(puerto); //Asignación del puerto
    mi_direccion.sin_addr.s_addr=inet_addr(ip_servidor); //Asignacion de la ip
    memset(&(mi_direccion.sin_zero),'\0',8); //sobreescribimos la estrucutra de 0 para empezar sin ningun dato por default
    // enlace
    int status=bind(sockettcp,(struct sockaddr*)&mi_direccion,sizeof(struct sockaddr)); //Asignamos un socket al puerto con la función bind( ) El primer parámetro es un descriptor del socket obtenido con la función socket( ) El segundo parámetro es un puntero a una estructura sockaddr con la dirección que hemos declarado anteriormente y el tercer parámetro es el tamaño de la estructura sockaddr_in.
    if(status==-1) //Si el estatus de el socket es -1 significa que no pudo ser conectado
    {
        printf("Error: error de enlace con el puerto %d.\n",puerto); //imprimimos el error
        return servidor_socket;
    }
    
    //En caso de que si se pudo conectar el socket
    // recuperamos el número de puerto  y socket en el que se inició el servidor
    socklen_t tamaño = sizeof(mi_direccion);
    if (getsockname(sockettcp, (struct sockaddr *)&mi_direccion, &tamaño) == -1) {
        
        //Si no se pudo obtener el socket
        printf("Error: al obtener el nombre del socket");
        return servidor_socket;
    }
    servidor_socket.puerto=ntohs(mi_direccion.sin_port); //Si obtenemos el socket guardamos su puerto
    servidor_socket.descriptor_socket=sockettcp; //Si obtenemos el socket guardamos su información
    listen(sockettcp,CONEXIONES); //Ponemos el socket en escucha
    return servidor_socket; //retornamos el socket creado
}

/*
    Maneja la acción de los peers como
        1. Conectar
        2. Publicar
        3. Buscar
    Procesa los mensajes provenientes de los peers
*/
void* hiloDeProcesoPeer(void *param)
{
    int nsfd=*((int *)param); //Si entra algun parametro lo castea a entero y lo asigna a una variable
    unsigned char datos[BUFFERMAXIMO]; //Reserva espacio para los datos ya sea para enviar o recibir
    char direccion_archivo[BUFFERMAXIMO]; //Reserva espacio para la ubicacion del archivo
    long unsigned tamaño_archivo; //Tamaño de archivo
    struct stat st;
    int chunk_count=0;

    int bytes_leidos=recv(nsfd,datos,BUFFERMAXIMO,0); //Almacenamos los mensajes que se reciban
    datos[bytes_leidos]='\0';
    if(bytes_leidos==0) //Si el peer salio de la conexion
    {
        printf("Conexión terminada !!\n");
        close(nsfd);
        return NULL;
    }
    else if(bytes_leidos==-1) //Si hubo un error al recibir datos del peer
    {
         printf("Error: Error al recibir datos. . \n");
         close(nsfd);
         return NULL;
    }
    //printf("Datos recibidos: %s; Longitud de datos:%d\n",datos,bytes_leidos);

    if(bytes_leidos>1) //Si fue correcto entramos en un switch
    {
        int identificadorTipo=datos[0]-48;
        switch(identificadorTipo)
        {
            case CONECTAR:  solicitudDeConexion(nsfd,datos); //1 lo conecta al servidor
                        break;
            case PUBLICAR: solicitudDePublicacion(nsfd,datos); //2 Maneja la peticion de publicar archivo
                        break;
            case DESCARGAR: solicitudDeDescarga(nsfd,datos); //3 Maneja la peticion para descargar un archivo
                        break;
        }
    }
    close(nsfd);
    return NULL;
}
/*
    Manejar solicitud de conexion
*/
void solicitudDeConexion(int sfd,char *datos) //Manejar la peticion de conectarse al servidor
{
    int identificadorTipo,puerto;
    char ipPeer[TAMAÑOSTRING]; //variables para guardar la ip del peer
    char idPeer[TAMAÑOSTRING]; //variables para guardar el id del peer
    int ku1;
    int ku2;
    informacion_peer *peer= (informacion_peer *)malloc(sizeof(informacion_peer)); //creamos un apuntador para saber la informacion del peer

    sscanf(datos,"%d %s %d %d %d %s",&identificadorTipo,ipPeer,&puerto,&ku1,&ku2,idPeer); //Leemos los datos de datos y los guardamos en variables
    if(strlen(idPeer) <= 1) //Si no existe un identificador del peer
    {
        sprintf(idPeer,"%s:%s",ipPeer,obtenerIDUnico()); //Le asignamos un ip y un identificador
    }
    
    send(sfd,idPeer,strlen(idPeer),0); //Enviamos el peer creado
    strcpy(peer->id,idPeer); //guardamos el id del peer enviado
    strcpy(peer->ip,ipPeer); //guardamos la ip del peer enviado
    peer->puerto=puerto; //guardamos el puerto del peer enviado
    peer->ku1 = ku1;
    peer->ku2 = ku2;
    sscanf(obtenerIDUnico(),"%llu",&(peer->ultimo_ping)); //Obtenemos un identificdor y lo asignammos al peer
    encriptar(ku1, ku2, llavesesion, peer->id);
    agregarPeerALista(peer); //Agregamos el peer a la lista de peers conectados
}

/*
    Agregar peers a la lista de peers activos.
    parametro:
        apuntador a informacion de peer para almacenarla.
    regreso:
        1 si es exitoso
*/
int agregarPeerALista(informacion_peer *peer)
{
    int p=0; //Un contador
    for(p=0;p<peers_conectados->contador_peers;p++) //Inicializa en 0 hasta que sea menor que el contador de los peers que estan aun conectados
    {
        if(strcmp(peer->id,peers_conectados->lista_peers[p]->id)==0) //Buscamos el peer que ingreso en la lista de peers activos
        {
            peers_conectados->lista_peers[p]=peer; //Lo agregagmos en la lista de peers si aun no fue agregado
            return 1;
        }
    }
    if(peers_conectados->contador_peers<PEERSMAXIMOS) //Si los peers conectados es menor que los peers que aun estan cnectados
    {
        peers_conectados->lista_peers[peers_conectados->contador_peers]=peer; //EL peer se agrega en la ultima posicion
        peers_conectados->contador_peers+=1; //Al contador de peers se le suma 1
        return 1;
    }
    return 0;
}
/*
    Compruebar si el peer esta activo o no
    Param:
        id: id de peer.
    regreso:
        1 si el peer esta vivo más
*/
int peerVivo(char *id)
{
    int p=0; //Contador
    for(p=0;p<peers_conectados->contador_peers;p++) //Inicializa en 0 hasta que sea menor que el contador de los peers que estan aun conectados
    {
        if(strcmp(id,peers_conectados->lista_peers[p]->id)==0) //Si el id que entro es igual a un peer con el mismo id, significa que esta vivo regresa 1
        {
            return 1;
        }
    }
    return 0;
}
/*
    Obtenga información de los peers que una estan activos.
    Parametro:
        ID del peer
    Regreso:
       la informacion del peer buscado que esta activo
*/
informacion_peer* obtenerInformacionPeerVivo(char *id)
{
    int p=0; //Contador
    for(p=0;p<peers_conectados->contador_peers;p++) //Inicializa en 0 hasta que sea menor que el contador de los peers que estan aun conectados
    {
        int a = strcmp(id,peers_conectados->lista_peers[p]->id); //Le asignamos a "a" el resultado de strcmp puede ser 0 o 1, si es 0 es que existe si es 1 es que no
        if(strcmp(id,peers_conectados->lista_peers[p]->id)==0) //Si encuentra el id en la lisya de peers activos
        {
            return peers_conectados->lista_peers[p]; //regresamos el peer
        }
    }
    return NULL;
}
/*
    Manejar la solicitud de publicación del peer;
*/
void solicitudDePublicacion(int sfd,char *datos)
{
    int identificadorTipo, puerto;
    informacion_archivo_publicado peer_archivoinfo ; //Tipo estructura para guardar los datos del archivo
    sscanf(datos,"%d %s %d  %s %s",&identificadorTipo,peer_archivoinfo.ip,&peer_archivoinfo.puerto,peer_archivoinfo.id,peer_archivoinfo.nombre_archivo); //Guardamos los datos en sus respectivos campos dentro de peer_archivoinfo
    int estatus=guardarArchivoPublicado(peer_archivoinfo); //Guardamos el estatus del archivo si pudo ser publicado o no
}

/*
    Guardar archivo publicado en la base de datos.
    regreso
        1 en caso de éxito y 0 en caso de fracaso;
*/
int guardarArchivoPublicado(informacion_archivo_publicado archivo_peer)
{
    char direccion_archivo[NOMBREARCHIVOMAXIMO]; //Reservamos memoria para guardar la ubicacion del archivo
    sprintf(direccion_archivo,"%s/%s",carpeta_por_defecto,bd_archivos_publicados); //gardamos en direccion_archivo, el nombre d ela carpeta y el registro en la base de datos
    FILE *archivoServidor; //Creamos un nuevo archivo con lo anteriomente guardado
    archivoServidor=fopen(direccion_archivo,"a"); //Abrimos el archivo
    if(!archivoServidor) //Si no se pudo encontrar
    {
        printf("Error: No se encontró el archivo %s\n",direccion_archivo);
        return 0;
    }
    fwrite(&archivo_peer,sizeof(archivo_peer),1,archivoServidor); //Si se pudo encontrar escribimos en el la informacion del archivo que entro como parametro
    fclose(archivoServidor); //Cerramos el archivo
    return 1;

}

/*
    Manejar la solicitud de busqueda del servidor.
*/
void solicitudDeDescarga(int sfd,char *datos)
{
    struct sockaddr_in p_addr; //Declaramos una estructura de este tipo para poder acceder a elementos de un socket
    int identificadorTipo,p_puerto;
    char nombreDescarga[NOMBREARCHIVOMAXIMO]; //Reservamos memoria para guardar el nombre del archivo a buscar
    char sdatos[BUFFERMAXIMO]; //Reservamos memoria para un buffer
    unsigned long long cur_time;
    sscanf(datos,"%d %s",&identificadorTipo,nombreDescarga); //Leemos los datos de datos y los guardamos en variables
    printf("Archivo buscado:%s\n",nombreDescarga); //Imprimimos el archivo que fue buscado por un peer

    char direccion_archivo[NOMBREARCHIVOMAXIMO]; //Reservamos memoria para un directorio
    informacion_archivo_publicado archivo_peer; //Estrucutra para guardar informacion de un archivo
    int bytes_leidos,i=0;
    sprintf(direccion_archivo,"%s/%s",carpeta_por_defecto,bd_archivos_publicados); //Guardamos la informacion de el folder pordefecto y el nombre del archivo en direccion_archivo
    FILE *archivoServidor; //Abrimos un archivo
    archivoServidor=fopen(direccion_archivo,"r"); //Lo abrimos para leer
    if(!archivoServidor) //Si el archivo esta vacío
    {
        printf("\n Error: archivo % s no encontrado. \n", direccion_archivo);
        fclose(archivoServidor);
        return;
    }
    // recuperar el número de puerto en el que se inició el servidor
    while((bytes_leidos=fread(&archivo_peer,sizeof(informacion_archivo_publicado),1,archivoServidor))>0) //Si encontramos el archivo solicitado
    {
        if(strstr(archivo_peer.nombre_archivo,nombreDescarga)!=NULL) //Buscamos el nombre del archivo, con una compracion de cadenas
        {
            informacion_peer *peerDueño=obtenerInformacionPeerVivo(archivo_peer.id); //Obtenemos la informacion del peer que lo publico
            sscanf(obtenerIDUnico(),"%llu",&cur_time); //Obtenemos un identificdor y lo asignammos a una variable de tiempo
            int peer_vivo= (peerDueño!=NULL && (cur_time - peerDueño->ultimo_ping) <= PULSO*1000 ) ? 1:0; //Si el peer que lo tiene esta vivo
            if(peer_vivo)
            {
                strcpy(archivo_peer.ip,peerDueño->ip); //Copiamos la ip del peer que lo publico
                archivo_peer.puerto=peerDueño->puerto; //El puerto

                sprintf(sdatos,"%s %s %d %s",archivo_peer.id,archivo_peer.ip,archivo_peer.puerto,archivo_peer.nombre_archivo); //Guardamos Los datos del archivo obtenido
                send(sfd,sdatos,strlen(sdatos),0); //enviamos la informacion de quien lo tiene
                recv(sfd,&datos,BUFFERMAXIMO,0); //Esperamos una respuesta
            }
        }
    }
    fclose(archivoServidor);
}

/*
    Mostrar el archivo publicado
*/
void mostrarArchivosPublicados()
{
    char direccion_archivo[NOMBREARCHIVOMAXIMO]; //Reservamos memoria para un directorio
    informacion_archivo_publicado archivo_peer; //Una estrucutura para saber los datos de el archivo
    int bytes_leidos,i=0;
    sprintf(direccion_archivo,"%s/%s",carpeta_por_defecto,bd_archivos_publicados); //Guardamos la direccion del folder y el archivo
    FILE *archivoServidor; //Declaramo un archivo
    archivoServidor=fopen(direccion_archivo,"r"); //Abrimos el archivo en la direccion
    if(!archivoServidor) //Si no existen archivos publicados
    {
        //printf("Error: File %s not found.\n", direccion_archivo);
        printf("\n-------------------------[Archivos publicados]---------------------------------\n\n");
        printf ( "\n\t Estado: aun no se publica ningún archivo" );
        printf("\n---------------------------------------------------------------------------\n");
        return;
    }
    printf("\n-------------------------[Archivos publicados]---------------------------------\n\n");
    //Si existen archivos publicados
    while((bytes_leidos=fread(&archivo_peer,sizeof(informacion_archivo_publicado),1,archivoServidor))>0)
    {
        informacion_peer *peerDueño=obtenerInformacionPeerVivo(archivo_peer.id); //Checamos quien tiene el archivo publicado
        if(peerDueño!=NULL)
                printf("%d) Ip: %s\tPuerto: %d\tNombre de archivo: %s\n",++i,peerDueño->ip,peerDueño->puerto,archivo_peer.nombre_archivo);
        else
                printf("%d) Ip: %s\tPuerto: %d\tNombre de archivo: %s\n",++i,archivo_peer.ip,archivo_peer.puerto,archivo_peer.nombre_archivo);
    }
    printf("\n---------------------------------------------------------------------------\n");
    fclose(archivoServidor);
}
/*
    Mostrar los pares que están conectados a este servidor.
*/
void mostrarPeersConectados()
{
    int p=0;
    unsigned long long cur_time;
    printf("\n-------------------------[Peers Activos]--------------------------------------\n\n");
    sscanf(obtenerIDUnico(),"%llu",&cur_time); //Obtenemos un id para esa consulta
    for(p=0;p<peers_conectados->contador_peers;p++) //checamos que peer aun esta conectado
    {
        int peer_vivo= (cur_time - peers_conectados->lista_peers[p]->ultimo_ping) <= PULSO*1000? 1:0;
        if(peer_vivo) //Si aun esta conectado se imprime
        {
            printf("%d)Ip:%s\tPuerto:%d\tKU[%d, %d]\t Id:%s\n",p+1,peers_conectados->lista_peers[p]->ip,peers_conectados->lista_peers[p]->puerto,peers_conectados->lista_peers[p]->ku1,peers_conectados->lista_peers[p]->ku2,peers_conectados->lista_peers[p]->id);
        }
    }
    printf("\n---------------------------------------------------------------------------\n");
}
void menu_acciones()
{
    printf("\n------------------------[Acciones del servidor]-----------------------------------\n");
    printf("\t\t1) Ver peers conectados\n");
    printf("\t\t2) Ver archivos publicados\n");
    printf("\t\t3) Mi información\n");
    printf("\tNota: Ingrese 0 para apagar el servidor y <cualquier número excepto los de arriba> para volver a seleccionar \n");
    printf("-------------------------------------------------------------------------\n");

}
//Imprimri la informacion del servidor
void miInformacion()
{
    printf("\n------------------------[Mi información]---------------------------------------\n");
    printf("\n\tIp\t:\t%s\n",ip_servidor);
    printf("\n\tPuerto\t:\t%d\n",puerto_servidor);
    printf("\n\tLlave sesion\t:\t%s\n", llavesesion);
    printf("-------------------------------------------------------------------------\n");
}
/*
    Menu para controlar las acciones del servidor
*/
void menu()
{
    int accion;
    menu_acciones();
    while(1)
    {
        printf("Tu acción:");
        scanf("%d",&accion);
        switch(accion)
        {
            case 0: exit(1);
                    break;
            case 1: mostrarPeersConectados();
                    break;
            case 2: mostrarArchivosPublicados();
                    break;
            case 3: miInformacion();
                    break;
            default:
                    menu_acciones();
                    break;
        }
    }
}
int main(int argc, char *argv[] )
{
    
    peers_conectados=(peer_conectado *)malloc(sizeof(peer_conectado));
    peers_conectados->contador_peers=0;
    strcpy(ip_servidor,"127.0.0.1"); //Direccion del servidor
    strcpy(llavesesion,"seminariodeseguridad"); //Direccion del servidor
    puerto_servidor=0; //puerto
    if(argc>1) //Si se le indicaron ip o puerto en especifico
    {

        if(argc >= 2 && strlen(argv[1])>1)
        {
            strcpy(ip_servidor,argv[1]);
        }
        if(argc >= 3 && strlen(argv[2])>1)
        {
            puerto_servidor=atoi(argv[2]);
        }
    }
    // crear carpeta predeterminada
    struct stat estatus = {0};
    if (stat(carpeta_por_defecto, &estatus) == -1) {
        mkdir(carpeta_por_defecto, 0777);
    }
    /***********************************************************/
    int status=iniciarServidor(puerto_servidor); //iniciamos el servidor
    if(status!=-1) //Si fue iniciado perfectamente mostramos el menu de acciones
    {
        menu();
    }
    printf("\n");
    return 0;
}
