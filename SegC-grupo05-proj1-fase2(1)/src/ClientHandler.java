package src;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Classe ClientHandler consiste numa thread que trata dos pedidos de um cliente
 * IoTServer Encaminha os pedidos para o servidor através do ServerManager
 */
public class ClientHandler implements Runnable {
    private static final String APLICACAO_FILE_PATH = "aplicacao.txt";
    private final SSLSocket clientSocket;
    private final ServerManager server;

    /**
     * Constroi um novo clientHandler
     *
     * @param clientSocket a socket do cliente
     * @param server       o servidor
     */
    public ClientHandler(SSLSocket clientSocket, ServerManager server) {
        this.clientSocket = clientSocket;
        this.server = server;
    }

    /**
     * Atraves da ligacao SSL com o cliente faz a autenticacao recebe pedidos de
     * um cliente IoTDevice
     */
    @Override
    public void run() {

        String userId = null;
        int deviceId = -1;

        try (SSLSocket clientSocket = this.clientSocket; ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

            ComunicacaoHandler communicationHandler = new ComunicacaoHandler(in, out);
            // 4.2.1 - AUTENTICACAO BASEADA EM CRIPTOGRAFIA ASSIMÉTRICA
            userId = (String) communicationHandler.lerResposta();
            long nonce = generateNonce();
            communicationHandler.enviarMensagem(nonce);
            if (server.isUser(userId)) {
                communicationHandler.enviarMensagem("USER-KNOWN");
                if (!receberAssinatura(communicationHandler, nonce, userId)) return;
                communicationHandler.enviarMensagem("OK-USER");
            } else {
                communicationHandler.enviarMensagem("USER-UNKNOWN");
                long nr = (long) communicationHandler.lerResposta();
                if (nonce != nr) {
                    communicationHandler.enviarMensagem("ERRO");
                    return;
                }
                if (!receberAssinaturaCertificado(communicationHandler, nonce, userId)) return;
                communicationHandler.enviarMensagem("OK-NEW-USER");
            }
            // 4.2.2 Confirmacao baseada em e-mail enviado ao utilizador
            int codigo = -2;
            int codigoCliente;
            do {
                codigo = autenticacaoDoisFatores(userId);
                codigoCliente = (int) in.readObject();
                if (codigo < 0 || codigoCliente != codigo) {
                    communicationHandler.enviarMensagem("2FA-NOK");
                } else {
                    communicationHandler.enviarMensagem("2FA-OK");
                }
            } while (codigoCliente != codigo);

            // 4.3 Atestacao Remota da Aplicacao
            deviceId = (int) communicationHandler.lerResposta();

            if (server.isDeviceLoggedIn(userId, deviceId)) {
                communicationHandler.enviarMensagem("NOK-DEVID");
                terminateClient(userId, deviceId);
                return;
            }
            server.addDispositivoLoggedIn(userId, deviceId);
            communicationHandler.enviarMensagem("OK-DEVID");
            nonce = generateNonce();
            communicationHandler.enviarMensagem(nonce);
            byte[] hash = (byte[]) communicationHandler.lerResposta();
			String clientApp = null;
			if(server.verificarHmac(APLICACAO_FILE_PATH)){
				clientApp = getClientApp();
			}
			else{
				System.err.println("Aplicacao remota foi alterada");
				terminateClient(userId, deviceId);
				return;
			}
			if(clientApp == null){
				System.err.println("Não foi possivel aceder ao file path da aplicação remota.");
				terminateClient(userId, deviceId);
				return;
			}
			
            byte[] hashLocal = communicationHandler.getHashNonceConcatenado(nonce, clientApp);
            if (Arrays.equals(hash, hashLocal)) {
                communicationHandler.enviarMensagem("OK-TESTED");
            } else {
                communicationHandler.enviarMensagem("NOK-TESTED");
                terminateClient(userId, deviceId);
            }
            while (true) {
                List<String> comando = (List<String>) in.readObject();
                switch (comando.get(0).toUpperCase()) {
                    case "CREATE":
                        String newDomainName = comando.get(1);
                        String mensagem = server.createDomain(newDomainName, userId) ? "OK" : "NOK";
                        communicationHandler.enviarMensagem(mensagem);
                        break;
                    case "ADD":
                        handleAdd(userId, comando.get(1), comando.get(2), communicationHandler);
                        break;
                    case "RD":
                        handleRd(userId, deviceId, comando.get(1), communicationHandler);
                        break;
                    case "ET":
                        handleEt(userId, deviceId, communicationHandler);
                        break;
                    case "EI":
                        handleEi(userId, deviceId, communicationHandler);
                        break;
                    case "RT":
                        handleRt(userId, comando.get(1), communicationHandler);
                        break;
                    case "RI":
                        handleRi(userId, comando.get(1), Integer.parseInt(comando.get(2)), communicationHandler);
                        break;
                    case "MYDOMAINS":
                        List<String> mydomains = server.getDeviceDomains(userId, deviceId);
                        communicationHandler.enviarMensagem(mydomains);
                        break;
                    default:
                        break;
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            terminateClient(userId, deviceId);
        } catch (ClassCastException e) {
            System.err.println("Mensagem inválida recebida: " + e.getMessage());
            terminateClient(userId, deviceId);
        }
    }

	/**
	 * Lê o nome da aplicacao do cliente atraves do ficheiro de aplicacao.txt
	 * @return o nome da aplicacao do cliente para realizar a atestacao remota
	 */
	private String getClientApp() {
		String clientApp = null;
		try (BufferedReader reader = new BufferedReader(new FileReader(APLICACAO_FILE_PATH))) {
			clientApp = reader.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return clientApp;

	}

	/**
     * Verifica se o utilizador tem permissáo para ler a imagem de um dado device
     * se sim retorna a imagem e a chave do dominio. Se nao existir imagem retorna NODATA.
     * Se o device não existir ou o user retorna NOID.
     *
     * @param userId               o utilizador que pede a imagem
     * @param userWanted           o userId do device dono da imagem
     * @param deviceWanted         o deviceId do dono da imagem
     * @param communicationHandler a stream que permite a comunicacao com o server
     */
    private void handleRi(String userId, String userWanted, int deviceWanted, ComunicacaoHandler communicationHandler) {
        PublicKey chavePublicaUser = server.getPublicKey(userId);

        if (!server.isUser(userWanted) || !server.checkIfUserHasDevice(userWanted, deviceWanted)) {
            communicationHandler.enviarMensagem("NOID");
            return;
        }
        Domain d = server.getFirstCommonDomain(userId, userWanted, deviceWanted);
        if (chavePublicaUser == null) {
            communicationHandler.enviarMensagem("NOPERM");
            return;
        }
        if(d == null){
            communicationHandler.enviarMensagem("NODATA");
            return;
        }

        byte[] imagem = server.getImagem(userWanted, deviceWanted, d.getName());
        if (imagem == null) {
            communicationHandler.enviarMensagem("NODATA");
            return;
        }
        byte[] wrappedKey = server.getWrappedKey(d.getName(), userId);
        if (wrappedKey == null) {
            communicationHandler.enviarMensagem("NOPERM");
            return;
        }
        communicationHandler.enviarMensagem("OK");
        communicationHandler.enviarMensagem(imagem);
        communicationHandler.enviarMensagem(wrappedKey);
    }

    /**
     * Trata do pedido de envio de imagem, envia as wrapped keys
     * cifradas com a chave publica do utilizador e envia para o
     * cliente, depois recebe do cliente as imagens cifradas
     * e armazena no servidor
     * @param userId o userId associado ao cliente
     * @param deviceId o device id associado ao device
     * @param communicationHandler a stream para comunicar com o cliente
     */
    private void handleEi(String userId, int deviceId, ComunicacaoHandler communicationHandler) {
        Map<String, byte[]> domainWrappedKeys = server.getDomainWrappedKeys(userId, deviceId);

        if (domainWrappedKeys == null || domainWrappedKeys.isEmpty()) {
            communicationHandler.enviarMensagem("NOK");
            return;
        }
        communicationHandler.enviarMensagem("OK");
        communicationHandler.enviarMensagem(domainWrappedKeys);

        Map<String, byte[]> imagensCifrada = (Map<String, byte[]>) communicationHandler.lerResposta();
        server.guardarImagemsCifrada(imagensCifrada, userId, deviceId);
    }

    /**
     * Verifica se um dado utilizador tem permissoes de acesso ao dominio, se
     * tiver entao envia as temperaturas cifradas desse dominio com a chave do
     * dominio e envia a chave do dominio que foi cifrada com a chave publica do
     * utilizador
     *
     * @param userId               string que identifica o (endereço de email
     *                             do) utilizador local.
     * @param dominio              nome que identifica o dominio
     * @param communicationHandler stream para enviar informacao ao cliente
     */
    private void handleRt(String userId, String dominio, ComunicacaoHandler communicationHandler) {
        if (!server.isDomain(dominio)) {
            communicationHandler.enviarMensagem("NODM");
            return;
        }
        if (!server.belongsToDomain(dominio, userId)) {
            communicationHandler.enviarMensagem("NOPERM");
            return;
        }

        PublicKey chavePublicaUser = server.getPublicKey(userId);
        if (chavePublicaUser == null) {
            communicationHandler.enviarMensagem("NOPERM");
            return;
        }
        Map<String, byte[]> temperaturasCifradas = server.getDeviceTemperatures(dominio);
        if (temperaturasCifradas.isEmpty()) {
            communicationHandler.enviarMensagem("NODATA");
            return;
        }
        communicationHandler.enviarMensagem("OK");
        byte[] wrappedKey = server.getWrappedKey(dominio, userId);
        communicationHandler.enviarMensagem(temperaturasCifradas);
        communicationHandler.enviarMensagem(wrappedKey);
    }

    /**
     * Verifica a quais dominios o dispositivo pertence e envia as chaves desses
     * dominios que estáo cifradas com a chave publica do utilizador para o
     * cliente, se nao existir nenhuma entao termina a operacao. Caso exista,
     * recebe as cópias das temperaturas cifradas e guarda no respectivo
     * dominio.
     *
     * @param userId               string que identifica o (endereço de email
     *                             do) utilizador local.
     * @param deviceId             número inteiro que identifica o dispositivo
     * @param communicationHandler stream para enviar informacao ao cliente
     */
    private void handleEt(String userId, int deviceId, ComunicacaoHandler communicationHandler) {
        Map<String, byte[]> domainWrappedKeys = server.getDomainWrappedKeys(userId, deviceId);
        communicationHandler.enviarMensagem(domainWrappedKeys);
        if (domainWrappedKeys == null || domainWrappedKeys.isEmpty()) {
            communicationHandler.enviarMensagem("NOK");
            return;
        }
        communicationHandler.enviarMensagem("OK");
        Map<String, byte[]> temperaturasCifradas = (Map<String, byte[]>) communicationHandler.lerResposta();
        server.guardarTemperaturasCifradas(temperaturasCifradas, userId, deviceId);
    }

    /**
     * Regista o dispositivo atual no dominio dado Caso o servidor aceite a
     * informação, o cliente deve receber uma mensagem do tipo OK. Caso o
     * utilizador atual não pertença ao domínio <dm>, ou o domínio não
     * exista o cliente deverá receber uma mensagem do tipo NOPERM ou NODM,
     * respetivamente
     *
     * @param userId               string que identifica o (endereço de email
     *                             do) utilizador local
     * @param deviceId             número inteiro que identifica o dispositivo
     * @param domainName           o nome do dominio
     * @param communicationHandler stream para enviar informacao ao cliente
     */
    private void handleRd(String userId, int deviceId, String domainName, ComunicacaoHandler communicationHandler) {

        if (domainName == null || deviceId < 0 || userId == null) {
            communicationHandler.enviarMensagem("NOK");
            return;
        }
        if (!server.isDomain(domainName)) {
            communicationHandler.enviarMensagem("NODM");
            return;
        }
        if (!server.belongsToDomain(domainName, userId)) {
            communicationHandler.enviarMensagem("NOPERM");
            return;
        }
        if (server.DeviceIsInDomain(domainName, deviceId, userId)) {
            communicationHandler.enviarMensagem("NOK");
            return;
        }
        server.addDeviceToDomain(domainName, userId, deviceId);
        communicationHandler.enviarMensagem("OK");
    }

    /**
     * Adiciona um novo utilizador ao dominio
     *
     * @param userId               o endereço de email do utilizador local
     * @param newUserId            o endereço de email do novo utilizador
     * @param domainName           o nome do dominio
     * @param communicationHandler stream para enviar informacao ao cliente
     */
    private void handleAdd(String userId, String newUserId, String domainName, ComunicacaoHandler communicationHandler) {
        try {
            if (!server.isDomain(domainName)) {
                communicationHandler.enviarMensagem("NODM");
                return;
            }
            if (!server.verificarOwner(userId, domainName)) {
                communicationHandler.enviarMensagem("NOPERM");
                return;
            }

            if (!server.isUser(newUserId)) {
                communicationHandler.enviarMensagem("NOUSER");
                return;
            }

            if (server.belongsToDomain(domainName, newUserId)) {
                communicationHandler.enviarMensagem("NOK");
                return;
            }
            communicationHandler.enviarMensagem("OK");
            byte[] chaveDominioCifrada = (byte[]) communicationHandler.lerResposta();
            if(!server.addNewUserToDomain(newUserId, domainName, chaveDominioCifrada)){
                communicationHandler.enviarMensagem("NOK");
                return;
            }
            communicationHandler.enviarMensagem("OK");
        } catch (ClassCastException e) {
            System.err.println("Mensagem inválida recebida: " + e.getMessage());
            communicationHandler.enviarMensagem("NOK");
        }
    }

    /**
     * Realiza operacoes para terminar o cliente em seguranca desconecta o
     * dispositivos da lista de dispositivos que estao ligados ao servidor e
     * armazena os dados para cumprir com persistencia
     *
     * @param userId   string que identifica o (endereço de email do)
     *                 utilizador local
     * @param deviceId número inteiro que identifica o dispositivo
     */
    private void terminateClient(String userId, int deviceId) {
        System.err.println("Disconnecting client...");
        server.desconectarDispositivo(userId, deviceId);
    }

    /**
     * Recebe a assinatura e o certificado do utilizador para verificar se a
     * assinatura é a esperada
     *
     * @param communicationHandler stream que recebe informacao do cliente
     * @param nonce                o nonce
     * @param userId               o email que identifica o utilizador
     * @return true se foi possivel verificar a assinatura do cliente, falso se
     * ocorreu erro ou assinatura inválida
     */
    private boolean receberAssinaturaCertificado(ComunicacaoHandler communicationHandler, long nonce, String userId) {
        try {
            byte[] assinaturaRecebida = (byte[]) communicationHandler.lerResposta();
            byte[] certBytes = (byte[]) communicationHandler.lerResposta();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate c = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            PublicKey publicKeyUser = c.getPublicKey();

            if (verificarAssinatura(nonce, publicKeyUser, assinaturaRecebida)) {
                String filepath = server.guardarCertificado(c, userId);
                return server.registarUser(userId, filepath);
            }
            return false;
        } catch (CertificateException e) {
            System.err.println("Erro ao verificar assinatura do certificado: " + e.getMessage());
            return false;
        }
    }

    /**
     * Recebe a assinatura procura certificado do utilizador local e obtem a
     * chave publica para verificar se a assinatura recebida é igual á
     * esperada
     *
     * @param communicationHandler stream que recebe assinatura do cliente
     * @param nonce                o nonce gerado
     * @param userId               o email que identifica utilizador
     * @return true se foi possivel verificar assinatura, falso se ocorreu erro
     * ou assinatura estava errada
     */
    private boolean receberAssinatura(ComunicacaoHandler communicationHandler, long nonce, String userId) {
        byte[] assinaturaRecebida = (byte[]) communicationHandler.lerResposta();
        String pathCertificate = server.getPathCertificate(userId);
        PublicKey publicKeyUser = this.getPublicKey(pathCertificate);
        return verificarAssinatura(nonce, publicKeyUser, assinaturaRecebida);
    }

    /**
     * Verifica se a assinatura recebida é igual á esperada
     *
     * @param nonce              o nonce enviado ao cliente
     * @param publicKeyUser      a chave publica do utilizador
     * @param assinaturaRecebida a assinatura recebida
     * @return true se foi possivel verificar assinatura, falso se ocorreu erro
     * ou assinatura estava errada
     */
    private boolean verificarAssinatura(long nonce, PublicKey publicKeyUser, byte[] assinaturaRecebida) {
        try {
            Signature s = Signature.getInstance("MD5withRSA");
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.putLong(nonce);
            byte[] buf = buffer.array();
            s.initVerify(publicKeyUser);
            s.update(buf);
            return s.verify(assinaturaRecebida);
        } catch (InvalidKeyException e) {
            System.err.println("Erro ao verificar assinatura, chave publica do utilizador tem formato errado: " + e.getMessage());
            return false;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro ao verificar assinatura, algoritmo para verificar assinatura nao é válido: " + e.getMessage());
            return false;
        } catch (SignatureException e) {
            System.err.println("Erro ao verificar assinatura: " + e.getMessage());
            return false;
        }
    }

    /**
     * Encontra o certificado que esta no path dado e obtem a chave publica
     * desse certificado
     *
     * @param pathCertificate o path para o certificado
     * @return a chave publica do certificado ou null em caso de erro
     */
    private PublicKey getPublicKey(String pathCertificate) {
        FileInputStream fis;
        Certificate c;
        try {
            fis = new FileInputStream(pathCertificate);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            c = certFactory.generateCertificate(fis);
            fis.close();
            return c.getPublicKey();
        } catch (FileNotFoundException e) {
            System.err.println("Ficheiro associado ao certificado nao foi encontrado: " + e.getMessage());
            return null;
        } catch (IOException e) {
            System.err.println("Ocorreu erro ao tentar ler do certificado: " + e.getMessage());
            return null;
        } catch (CertificateException e) {
            System.err.println("Erro a aceder ao certificado do user no servidor" + e.getMessage());
            return null;
        }
    }

    /**
     * Realiza a Confirmação baseada em e-mail enviado ao utilizador Gera o
     * código C2FA, que corresponde a um número aleatório de cinco dígitos
     * (entre 00000 e 99999). enviar o C2FA por e-mail ao utilizador
     *
     * @param userId o endereco de email do utilizador
     * @return o numero aleatorio de 5 digitos gerado (codigo)
     */
    private int autenticacaoDoisFatores(String userId) {
        int codigo = gerarCodigo();
        int codeServer = enviarCodigo(userId, codigo);
        if (codeServer == 401 || codeServer == -1) {
            return -1;
        }
        return codigo;
    }

    /**
     * Envia o codigo 2FA ao cliente
     *
     * @param userId o (endereço de email do) utilizador local para o qual vai
     *               ser enviado o código
     * @param apikey o código que permite aceder a api de autenticacao
     */
    private int enviarCodigo(String userId, int apikey) {
        String url = "https://lmpinto.eu.pythonanywhere.com/2FA?e=" + userId + "&c=" + apikey + "&a=" + server.getApikey();
        URL obj;
        int responseCode = -1;
        try {
            obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("GET");
            responseCode = con.getResponseCode();
            con.disconnect();
        } catch (IOException e) {
            System.err.println("Erro ao tentar aceder a 2FA-API.");
            return responseCode;
        }

        if (responseCode == 401) {
            System.err.println("Não está autorizado a receber código, verifique emaill e se api key está correta.");
        } else if (responseCode == -1) {
            System.err.println("Nao foi possivel obter o codigo.");
        }
        System.out.println("Resposta do servidor 2FA:" + responseCode);
        return responseCode;
    }

    /**
     * Gera um numero aleatório entre 0 e 9999
     *
     * @return o numero aleatorio gerado
     */
    private int gerarCodigo() {
        // Gerar um número aleatório entre 0 e 99999
        Random random = new Random();
        return random.nextInt(100000);
    }

    /**
     * Gena um nonce
     *
     * @return o nonce
     */
    public static long generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.nextLong();
    }

}