Este trabalho realiza todas as funcionalidades pedidas.

COMO COMPILAR

Na pasta SegC-grupo05-proj1-fase2 correr os seguintes comandos:

javac src/IoTDevice.java src/ComunicacaoHandler.java

javac src/IoTServer.java src/ServerManager.java src/UserManager.java src/DomainManager.java src/Domain.java src/FilesHandler.java src/ComunicacaoHandler.java src/ClientHandler.java

EXECUTAR JAVA COMPILADO

java src/IoTServer <port> <password-cifra> <keystore> <password-keystore> <2FA-APIKey>


java src/IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>



COMO EXECUTAR OS JARS

java -jar IoTServer.jar <port> <password-cifra> <keystore> <password-keystore> <2FA-APIKey>

Para executar é preciso ter acesso a uma <2FA-APIKey>, chave dada a cada grupo de alunos para o processo de
autenticação de dois fatores definido na Secção 4.2.


java -jar IoTDevice.jar <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>
