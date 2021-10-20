## CRUD Stand for: Create, Read, Update, Delete

import json
import sys
import requests
import base64
import pandas as pd

###Aqui nos deshacemos de un warning de seguridad porque el certificado no cumple con los estandares del RFC
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

MIN_ARGS = 3;
MAX_ARGS = 4;

# This function manages authentication-related requests to the server located at the named URL.
# url : URL string to which the request is sent.
# headers: Custom headers to be used for the request.
# cert_loc: Location of the certificate file.
def auth_request(url, headers, cert_loc):
    # Initialize response
    resp = None

    # Do the POST to create the tokens
    ## Usamos HTTPS porque es el unico puerto que admite el FMC
    if url.startswith("https"):
        try:
            resp = requests.post(url, headers=headers, verify=False)   ## Cambiamos el Verify a False para evitar el uso de certificado
            print(resp)   ##Este print nos devuelve el codigo de retorno de la solicitud post por HTTP
            if (resp == None):
                raise ValueError("Response is undefined")
            if (resp.status_code != 204):
                msg = "Error Status Code: %d in response" % resp.status_code
                raise ValueError(msg)            ## El Raise es un except pero tiene que ir acompañado
                                                 ## de un if para validar el error y el error puede se puede definir personalizado
        except Exception:                        ## El exception normal que prueba un bloque de codigo
            print("Error Handle auth_request")
    ## Dentro de este Else se ejecuta si un caso no usamos HTTPS (no recomendado)
    else:
        resp = requests.post(url, headers=headers)

    return resp

# This function logs into a server with a basic username/password authorization.
# server: The server name string to be used.
# username: The username string.
# password: The password string.
# cert_loc: Location of the certificate file.
def login(server, username, password, cert_loc):
    # API path for generating token
    api_path = "/api/fmc_platform/v1/auth/generatetoken"

    # Constructing the complete URL
    url = server + api_path

    # Creating basic authorization header using username and password that is base64 encoded
    ##Aqui le hicimos un cambio por la actualizacion de la libreria base64:
    ##En primer lugar armamos el string
    base64string_byte = ('%s:%s' %(username, password))
    #print(base64string_byte)
    ##En segundo lugar codificamos el string a ascii byte, pero en este paso el encode agrega la letra "b'" en
    ##referencia binario por eso no se podia loggear con la solicitud Post
    message_bytes = base64string_byte.encode('ascii')
    print(message_bytes)
    ##En este tercer paso se hace la conversion de Byte a base64 pero en este paso agregaba "b'"
    ##por esa razon convertimos el string directamente a base64 con una aplicacion online
    ##referencia armar header authorization: https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Authorization
    base64string = base64.b64encode(message_bytes)
    ##string convertido a base64 en: https://www.base64encode.org/
    ##String para FMC
    authstring = "Basic "base64encodedmessage"
    print(authstring)
    headers = {'Authorization' : authstring}

    #Generate tokens by posting the data
    ##En esta funcion se le manda URL y el header de autorizacion con el username y password
    try:
       resp = auth_request(url, headers, cert_loc)
    except Exception:
       print("Error Handle login")
    ##En este caso retorna los headers para authorization y tokens
    return {'X-auth-access-token': resp.headers['X-auth-access-token'], 'X-auth-refresh-token': resp.headers['X-auth-refresh-token']}

# This function performs logs out of a server.
# server: The server name.
# access_token: The access token string.
# cert_loc: Location of the certificate file.
def logout(server, access_token, cert_loc):
    # API path for generating token
    api_path = "/api/fmc_platform/v1/auth/revokeaccess"

    # Constructing the complete URL
    url = server + api_path

    # Create custom header for revoke access
    headers = {'X-auth-access-token' : access_token}

    # Generate tokens by posting the data
    try:
        auth_request(url, headers, cert_loc)
    except Exception:
        print("Error Handle logout")

    return (0)

# This the main method.
# This method expects at least 3 arguments and a max of 4 arguments
# when executed from the command line.
# Usage: "python auth_util.py server username password <cert_loc>"
# server: The server address.
# username: The username for basic authorization.
# password: The password for basic authorization.
# cert_loc: Location of the certificate file.
def main():
    if len(sys.argv) < MIN_ARGS:
        sys.exit("Insufficient inputs. The inputs must have at least 3 arguments \"python auth_util.py <server_addr> <username> <password> <location of certificate>\"")

    # Get the server address
    server = sys.argv[1]

    # Get the username
    username = sys.argv[2]
    print(username)
    # Get the password
    password = sys.argv[3]
    print(password)

    # Get the SSL certification check info
    cert_loc = False
    if len(sys.argv) > MAX_ARGS:
        cert_loc = sys.argv[MAX_ARGS]

    result = login(server, username, password, cert_loc)

    access_token = result.get('X-auth-access-token');
    refresh_token = result.get('X-auth-refresh-token');
    if (access_token != None and refresh_token != None):
        print("\nAccess tokens and Refresh tokens exist.")
        print("Access token: %s" % access_token)
        print("Refresh token: %s\n" % refresh_token)
    ##    result_logout = logout(server, result['X-auth-access-token'], cert_loc)
    ##    print("Logout Results: %d" % result_logout)
    else:
        print("Access tokens and refresh tokens does not exist.")


    ##Creacion de los objetos para Post
    post_data_url = {
            "type": "Url",
            "name": "UrlObject1_test1",
            "description": "url object 1",
            "url": "http://www.uni.edu.ni"
        }
    ##Cargamos las URL desde un archivo CSV
    data_url = pd.read_csv("General_url_implementar.csv", dtype="string")


    ##Obtenemos el URL API Path de la pagina de api-explorer del FMC:
    ##Domain UUID
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urls"

    url_API = server + api_path

    ##Creamos los headers para el post de URL
    headers_url = {'Content-Type': 'application/json'}
    headers_url['X-auth-access-token'] = access_token

    try:
        for x in data_url.iloc[:, 0]:
            post_data_url['name'] = "General_" + x
            post_data_url['description'] = "URL Block General"
            post_data_url['url'] = x

            r = requests.post(url_API, data=json.dumps(post_data_url), headers=headers_url, verify=False);
            status_code = r.status_code
            resp = r.text
            if status_code == 201 or status_code == 202:
                print("Post was successful for " + post_data_url["name"])
                # json_resp = json.loads(resp)
                # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()


# Stand Alone execution
if __name__ == "__main__":
    main()
