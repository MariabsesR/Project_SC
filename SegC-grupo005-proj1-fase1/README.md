GRUPO 5

Este trabalho implementa todas as funcionalidades pedidas.
Durante a execução os dados são mantidos em hashmap, ao desconectar o IoTServer ou o IoTDevice os dados são guardados em ficheiros.
Nome dos dominios é case sensitive

Este trabalho contem:
 - o código do trabalho;
 - os ficheiros jar (cliente e servidor) para execução do projeto;
 - o ficheiro aplicacao.txt com os valores hardcoded para a validação do cliente

COMO COMPILAR:

javac IoTServer.java ClientHandler.java IoTDevice.java

COMO EXECUTAR:

Programa cliente: 
java -jar IoTDevice.jar <serverAddress> <dev-id> <user-id>

nota: O formato de serverAddress é o seguinte: <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o porto é opcional.

Programa do servidor (inserir porto não é obrigatório):
java -jar IoTServer.jar <port>

Ao inserir comandos e os argumentos de execução deve ter o cuidado de nao inserir espaços em branco extras pois estes serao contados como caracteres.


