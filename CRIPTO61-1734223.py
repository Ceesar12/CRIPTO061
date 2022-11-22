import os
import pyfiglet as header
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey
import time

def nom_equipo():
    os.system("cls")
    print("Integrantes:\n - César Alejandro Rodríguez Pérez - 1734223\n - Carlos Adrián Soto Serna - 1812030\n - Jordi Roel Delgado Ortega - 1848005\n - José Osvaldo Puga Leija - 1990132\n - Víctor Horacio Cruz Álvarez - 2034192\nMateria: Criptografía.\nGrupo: 061.\n\n")
    os.system("pause")
    os.system("cls")
    
def llave(username: str, seed: bytes):
    llav = SigningKey(seed)
    raw = llav.sign(username.encode("utf-8"))
    return raw

def generador():
    gene = SigningKey.generate()    
    return gene._seed

def encriptar(data: bytes, password: bytes):
    encrypted_array: list = []
    i = 0
    for j in data:
        encrypted_array.append(((j + password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i = 0    
    return b''.join(encrypted_array)

def crearF(data: bytes, path: str):
    with open(path, "wb") as file:
        file.write(data)    

def registrar(usuario: str, contraseña: str):
    fuga: bytes = generador()
    sig: dict = llave(usuario, fuga)
    crearF(encriptar(fuga, contraseña.encode("utf-8")), "{}.key".format(usuario))  
    os.system("cls")  
    print("Se ha regitrado con éxito un usuario")
    crearF(sig, "{}.cer".format(usuario)) 
    print("También se generó el certificado y la llave")
    os.system("pause")
    os.system("cls")

def ingresar(num, contra):
    aux=" "
    while(num == True):
        os.system("cls")
        print("1: Cifrar Mensaje.\n2: Desifrar Mensaje.\n3: Cerrar Sesión.\n")    
        opc = int(input("Selecciona una opción: "))
        if opc==1:
            os.system("cls")
            print("Cifremos tu mensaje...")
            mensaje = input("Por favor, escribe tu mensaje. En de que sea un mensaje largo se recomienda copiar: ")  
            aux=cifrado(mensaje, 3)
            os.system("\n\npause")
            os.system("cls")
        if opc==2:
            if aux==" ":
                print("No hay mensaje para descifrar. Favor de encriptar un mensaje en el menú anterior.")
                os.system("\n\npause")
                os.system("cls")
                break
            conaux=input("Ingresa la contraseña para poder desencriptar el mensaje: ")
            if conaux==contra:
                os.system("cls")
                print("Escribe o pega el mensaje a descencriptar: ",aux)
                codigoC = input("Ingresa el mensaje que quieras descifrar: ")
                os.system("cls")
                decifrar(codigoC, 3)
            else:
                print("Contraseña incorrecta. Cerrando el programa por seguridad.")
                os.system("\n\npause")
                os.system("cls")
                exit()
        if opc==3:
            print("Cerrando sesión...")
            os.system("\n\npause")
            exit()
            os.system("cls")
    

def cifrado(mensaje, llave_cesar):  
    global simbolos
    simbolos = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!·$%&/()=????¿"
    resultado = ""
    for simbolo in mensaje:
        if simbolo in simbolos:
            indiceSimbolo = simbolos.find(simbolo)
            indiceNuevo = indiceSimbolo + llave_cesar
            if indiceNuevo >= len(simbolos):
                indiceNuevo = indiceNuevo - len(simbolos)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(simbolos)
            resultado = resultado + simbolos[indiceNuevo]
        else:
            resultado = resultado + simbolo
    crearF(encriptar(resultado.encode("utf-8"), contra_ces), "cifrado.txt")
    os.system("cls")  
    print("El mensaje ha sido encriptado : {}\nSe acaba de generar el archivo cifrado.txt".format(resultado))
    return resultado
    os.system("\n\npause")
    os.system("cls")
    

def decifrar(mensaje, saltos): 
    resultado = ""
    for simbolo2 in mensaje:
        if simbolo2 in simbolos:
            indiceSimbolo = simbolos.find(simbolo2)
            indiceNuevo = indiceSimbolo - saltos
            if indiceNuevo >= len(simbolos):
                indiceNuevo = indiceNuevo - len(simbolos)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(simbolos)
            resultado = resultado + simbolos[indiceNuevo]
        else:
            resultado = resultado + simbolo2
    os.system("cls")
    print("El mensaje ha sido descencriptado: " + resultado)
    os.system("\n\npause")
    os.system("cls")

def leerA(path: bytes):
    try:
        with open(path, "rb") as file:
            return file.read()
    except FileNotFoundError:          
        print("El archivo no existe")
        os.system("\n\npause")  
        exit()

def desencriptar(data: bytes, password: bytes):
    try:
        decrypted_array: list = []
        i=0
        for d in data:
            decrypted_array.append(((d - password[i]) % 256).to_bytes(1, "big"))
            i+=1
            if i >= len(password):
                i = 0        
        return b''.join(decrypted_array)
    except Exception:
        pass

def verificar(llaveprivada: bytes, certificado: bytes, password: str):
    global valor
    global contra_ces
    wer: bytes = desencriptar(leerA(llaveprivada), password.encode("utf-8"))
    signed_raw: bytes = leerA(certificado)    
    verify_key = SigningKey(wer).verify_key    
    try:
        verify_key.verify(signed_raw)
        os.system("cls")
        print("Verificación exitosa.")
        os.system("\n\npause")
        os.system("cls")
        contra_ces = password.encode("utf-8")
        valor = True
    except BadSignatureError:
        os.system("cls")
        print("La verificación no fue exitosa")
        os.system("\n\npause")
        os.system("cls")
        valor = False

def main():
    while(True):
        print("Menú Principal:\n1: Registrar nuevo usuario y certificado\n2: Iniciar sesión con usuario y certificados.\n3: Integrantes del equipo\n4: Salir.")
        try:
            numero = int(input("\nSelecciona una opción ingresando un número: "))
        except:
            os.system("cls")
            print("Error, no puedes ingresar letras en esta sección. Favor de intentar nuevamente.\n\n")
            os.system("pause")
            os.system("cls")
            main()
        if numero == 1:
            while(True):
                os.system("cls")
                usuario = input("Ingresa el nombre del usuario : ")
                contraseña = input("Ingresa la contraseña : ")  
                if not usuario or not contraseña:
                    os.system("cls") 
                    print("Por favor, Ingrese la contraseña y el usuario para poder ejecutar el programa")
                    os.system("\n\npause")
                else:
                    registrar(usuario, contraseña)
                    break
            
        if numero == 2:
            cont=0
            intentos=3
            while(True):
                os.system("cls")
                print("Ingresa los nombres de los archivos key y cer. Ejemplos:\nNombreDeArchivo.key\nNombreDeArchivo.cer\n\nnúmero de intentos: ",intentos)
                certificado: bytes = input("\n\nIngresa el certificado (.cer): ")
                claveP: bytes = input("Ingresa la clave privada (.key): ")
                contra = input("Ingrese la ontraseña de la clave privada: ") 
                if not certificado or not claveP or not contra:
                    cont=cont+1
                    os.system("cls")
                    print("No se ingreso uno o varios archivos. Favor de ingresarlos de manera correcta.")
                    intentos=intentos-1
                    os.system("\npause")
                    if cont==3:
                        os.system("cls")
                        print("Se a intentado 3 veces. Cerrando el programa por seguridad.")
                        time.sleep(3)
                        os.system("\n\npause")
                        exit()
                        os.system("cls")
                else:
                    verificar(claveP, certificado, contra)
                    break
            ingresar(valor, contra)
        if numero==3:
            nom_equipo()
        if numero == 4 :
            os.system("cls")
            print("¡¡Muchas gracias por usar este programa :D!!")
            os.system("pause")
            return False

if __name__ == "__main__":
    main()
