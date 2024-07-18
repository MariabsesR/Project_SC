package src;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.KeySpec;
import java.util.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;

public class IoTDevice {
    final static int DEFAULT_PORT = 12345;
    final static String COMMANDS_MENU =
            "Escolha um dos seguintes comandos:\n" +
                    "CREATE <dm> Criar dominio - utilizador é Owner\n" +
                    "ADD <user1> <dm> <password-dominio> Adicionar utilizador <user1> ao domínio <dm>\n" +
                    "RD <dm> Registar o Dispositivo atual no domínio <dm>\n" +
                    "ET <float> Enviar valor <float> de Temperatura para o servidor.\n" +
                    "EI <filename.jpg> Enviar Imagem <filename.jpg> para o servidor.\n" +
                    "RT <dm> Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões.\n" +
                    "RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões.\n" +
                    "COMANDO:";
    private final String serverAddress;
    private final int port;
    private final int deviceId;
    private final String userId;
    private final String truststorePath;
    private final String keystorePath;
    private final String keystorePassword;
    private final Map<String, byte[]> saltMap;
    private final Map<String, Integer> iterationsMap;
    private final KeyStore truststore;
    private KeyStore userKeyStore;

    public IoTDevice(String serverAddress, int port, int deviceId, String userId, String truststorePath, String keystorePath, String keystorePassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        this.serverAddress = serverAddress;
        this.port = port;
        this.deviceId = deviceId;
        this.userId = userId;
        this.truststorePath = truststorePath;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        saltMap = new HashMap<>();
        iterationsMap = new HashMap<>();
        this.truststore = KeyStore.getInstance("JCEKS");
        try (InputStream truststoreStream = new FileInputStream(truststorePath)) {
            truststore.load(truststoreStream, keystorePassword.toCharArray());
        }

        loadParametersFromFile();
    }

    private void loadParametersFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader(userId + "_parametros_dominio.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(", ");
                if (parts.length == 3) {
                    String domain = parts[0];
                    byte[] salt = Base64.getDecoder().decode(parts[1]);
                    int iterations = Integer.parseInt(parts[2]);
                    saltMap.put(domain, salt);
                    iterationsMap.put(domain, iterations);
                }
            }
        } catch (Exception e) {
            System.out.println("User ainda não tem parametros de dominio guardados.");
        }
    }

    public static void main(String[] args) {
        if (args.length != 6) {
            System.err.println("Usage: src.IoTDevice <serverAddress>[:PORT] <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>");
            System.exit(1);
        }

        String[] serverAddressParts = args[0].split(":");
        int port = DEFAULT_PORT;
        String serverAddress = args[0];

        if(serverAddressParts.length>1) {
            port = verificarPorto(serverAddress);
            serverAddress = serverAddressParts[0];
        }
        String truststorePath = args[1];
        String keystorePath = args[2];
        String keystorePassword = args[3];

        int deviceId = verificarDeviceId(args[4]);
        String userId = args[5];
        IoTDevice device = null;
        try {
            device = new IoTDevice(serverAddress, port, deviceId, userId, truststorePath, keystorePath, keystorePassword);
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            System.err.println("Error loading truststore.");
            System.exit(1);
        }
        device.start();
    }

    private static int verificarDeviceId(String id) {
        int deviceId = -1;
        try {
            deviceId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            System.err.println("Device ID must be an integer");
            System.exit(1);
        }
        return deviceId;
    }

    private static int verificarPorto(String serverAddress) {
        String[] serverAddressParts = serverAddress.split(":");
        int port = DEFAULT_PORT;
        if (serverAddressParts.length == 2) {
            try {
                port = Integer.parseInt(serverAddressParts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number: " + serverAddressParts[1]);
                System.exit(1);
            }
        }
        return port;
    }

    public void start() {
        this.userKeyStore = loadKeystore();

        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", keystorePassword);
        SocketFactory sf = SSLSocketFactory.getDefault();
        try (SSLSocket clientSocket = (SSLSocket) sf.createSocket(serverAddress, port); ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream()); Scanner scanner = new Scanner(System.in)) {

            ComunicacaoHandler communicationHandler = new ComunicacaoHandler(in, out);
            String mensagem;
            // 4.2.1 - AUTENTICACAO BASEADA EM CRIPTOGRAFIA ASSIMÉTRICA
            communicationHandler.enviarMensagem(this.userId);
            long nonce = (long) communicationHandler.lerResposta();
            String flag = (String) communicationHandler.lerResposta();
            System.out.println(flag);
            out.flush();
            if (flag.equals("USER-UNKNOWN")) {
                efetuarRegisto(userKeyStore, nonce, communicationHandler);
            } else {
                efetuarRegistoUtilizadorConhecido(nonce, communicationHandler);
            }
            mensagem = (String) communicationHandler.lerResposta();
            System.out.println(mensagem);
            out.flush();

            if (mensagem.equals("ERRO")) {
                System.err.println("Erro no registo do user, terminar ligação.");
                System.exit(1);
            }
            // 4.2.2 Confirmacao baseada em email enviado ao utilizador
            do {
                System.out.print("Introduza o código enviado pelo servidor: ");
                out.flush();
                String codigostring = scanner.nextLine();
                int codigo = Integer.parseInt(codigostring);
                communicationHandler.enviarMensagem(codigo);
                mensagem = (String) communicationHandler.lerResposta();
                System.out.println(mensagem);
                out.flush();
            } while (mensagem.equals("2FA-NOK"));

            // 4.3 Atestacao Remota da aplicacao
            communicationHandler.enviarMensagem(this.deviceId);
            mensagem = (String) communicationHandler.lerResposta();
            System.out.println(mensagem);
            if (mensagem.equals("NOK") || mensagem.equals("NOK-DEVID")) {
                System.err.println("A terminar ligação.");
                System.exit(1);
            }

            nonce = (long) communicationHandler.lerResposta();

            byte[] hash = communicationHandler.getHashNonceConcatenado(nonce, "IoTDevice.jar");
            communicationHandler.enviarMensagem(hash);

            // passo 4.3.2) enviar hash
            mensagem = (String) communicationHandler.lerResposta();
            System.out.println(mensagem);
            out.flush();
            if (mensagem.equals("NOK-TESTED")) {
                System.err.println("A terminar ligação.");
                return;
            }
            funcionalidadesPrompt(scanner, communicationHandler);
        } catch (IOException e) {
            System.err.println("Erro ao comunicar com servidor.");
            System.out.println("Programa terminado.");
        }
    }

    private void efetuarRegisto(KeyStore clientKeystore, long nonce, ComunicacaoHandler communicationHandler) {
        PrivateKey pk = null;
        try {
            pk = (PrivateKey) clientKeystore.getKey(userId, keystorePassword.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("IoTDevice não consegue aceder a privateKey cliente");
            System.exit(1);
        }
        Signature s = null;
        try {
            s = Signature.getInstance("MD5withRSA");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("IoTDevice não consegue identificar algoritmo de instancia da assinatura do registo");
            System.exit(1);
        }
        try {
            s.initSign(pk);
        } catch (InvalidKeyException e) {
            System.err.println("IoTDevice privateKey é inválida");
            System.exit(1);
        }

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(nonce);
        byte[] buf = buffer.array();
        try {
            s.update(buf);
        } catch (SignatureException e) {
            System.err.println("IoTDevice nao foi possivel registar o user devido a assinatura");
            System.exit(1);
        }
        communicationHandler.enviarMensagem(nonce);
        try {
            communicationHandler.enviarMensagem(s.sign());
        } catch (SignatureException e) {
            System.err.println("IoTDevice nao foi possivel registar o user devido a assinatura");
            System.exit(1);
        }

        Certificate[] certs = new Certificate[0];
        try {
            certs = clientKeystore.getCertificateChain(userId);
        } catch (KeyStoreException e) {
            System.err.println("IoTDevice nao consegue encontrar certificado do user: " + userId);
            System.exit(1);
        }
        try {
            communicationHandler.enviarMensagem(certs[0].getEncoded());
        } catch (CertificateEncodingException e) {
            System.err.println("IoTDevice erro a enviar certificado do user: " + userId);
            System.exit(1);
        }
    }

    private void efetuarRegistoUtilizadorConhecido(long nonce, ComunicacaoHandler communicationHandler) {
        PrivateKey pk = getPrivateKeyUser();

        if (pk == null) {
            return;
        }
        Signature s = null;
        try {
            s = Signature.getInstance("MD5withRSA");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("IoTDevice não consegue identificar algoritmo de instancia da assinatura do registo");
            System.exit(1);
        }
        try {
            s.initSign(pk);
        } catch (InvalidKeyException e) {
            System.err.println("IoTDevice privateKey é inválida");
            System.exit(1);
        }

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(nonce);
        byte[] buf = buffer.array();
        try {
            s.update(buf);
        } catch (SignatureException e) {
            System.err.println("IoTDevice nao foi possivel registar o user devido a assinatura");
            System.exit(1);
        }
        // envia apenas a sginature e nao o nonce nem certificado ao contrario
        // do ponto 4.2.1 a);
        try {
            communicationHandler.enviarMensagem(s.sign());
        } catch (SignatureException e) {
            System.err.println("IoTDevice nao foi possivel registar o user devido a assinatura");
            System.exit(1);
        }
    }

    private PrivateKey getPrivateKeyUser() {
        try {
            return (PrivateKey) userKeyStore.getKey(userId, keystorePassword.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("IoTDevice não consegue aceder a privateKey cliente");
            System.exit(1);
        }
        return null;
    }

    private KeyStore loadKeystore() {
        KeyStore clientKeystore = null;
        try {
            clientKeystore = KeyStore.getInstance("jceks");
            FileInputStream fis = new FileInputStream(keystorePath);
            clientKeystore.load(fis, keystorePassword.toCharArray());

        } catch (FileNotFoundException | KeyStoreException e) {
            System.err.println("IoTDevice não conseguiu encontrar keystore");
            System.exit(1);
        } catch (CertificateException e) {
            System.err.println("IoTDevice não conseguiu carregar algum dos certificados na keystore");
            System.exit(1);
        } catch (IOException e) {
            System.err.println("IoTDevice password incorreta ou inexistente para a keystore");
            System.exit(1);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("IoTDevice não consegue carregar keystore");
            System.exit(1);
        }
        return clientKeystore;
    }

    private void funcionalidadesPrompt(Scanner sc, ComunicacaoHandler communicationHandler) throws IOException {
        System.out.print(COMMANDS_MENU);
        String cmds;
        String[] splitedCmds;
        String response;

        while (true) {
            if (sc.hasNextLine()) {
                cmds = sc.nextLine();
                splitedCmds = cmds.split("[\\s:]");
                ArrayList<String> commands = new ArrayList<>(Arrays.asList(splitedCmds));
                switch (commands.get(0).toUpperCase()) {
                    case "CREATE":
                        if (commands.size() == 2) {
                            communicationHandler.enviarMensagem(commands);
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            communicationHandler.flush();
                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "RD":
                        if (commands.size() == 2) {
                            communicationHandler.enviarMensagem(commands);
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            communicationHandler.flush();
                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "ADD":
                        if (commands.size() == 4) {
                            String user = commands.get(1);
                            String dominio = commands.get(2);
                            String passwordDominio = commands.get(3);
                            commands.remove(3);
                            communicationHandler.enviarMensagem(commands);
                            response = (String) communicationHandler.lerResposta();
                            if(!response.equals("OK")) {
                                System.out.println(response);
                                communicationHandler.flush();
                                break;
                            }
                            // 1 - cifrar password com parametros dominio
                            SecretKey sharedKey = gerarPasswordDominio(dominio, passwordDominio);
                            if (sharedKey == null) {
                                return;
                            }
                            // 2 - cifrar com chave publica do utilizador novo
                            byte[] wrappedKey = cifrarComChavePublicaNovoUser(sharedKey, user, dominio);
                            communicationHandler.flush();
                            if (wrappedKey == null) {
                                break;
                            }
                            communicationHandler.enviarMensagem(wrappedKey);
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            communicationHandler.flush();
                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "ET":
                        if (commands.size() == 2) {
                            String temperatura = commands.get(1);
                            if (isTemperature(temperatura)) {
                                commands.remove(1);
                                communicationHandler.enviarMensagem(commands);
                                Map<String, byte[]> wrappedKeys = getWrappedKeys(communicationHandler);
                                response = (String) communicationHandler.lerResposta();
                                System.out.println(response);
                                if(response.equals("NOK") || wrappedKeys == null) break;
                                enviarCopiasCifradas(temperatura, wrappedKeys, communicationHandler);
                            } else {
                                System.out.println("Invalid temperature value: " + temperatura);
                            }
                            communicationHandler.flush();
                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "EI":
                        if (commands.size() == 2) {
                            communicationHandler.enviarMensagem(commands);
                            String pathImagem = splitedCmds[1];
                            File imagem = new File(pathImagem);
                            if (!imagem.exists()) {
                                System.err.println("Ficheiro não existe.");
                                break;
                            }
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            if (response.equals("NOK")) break;

                            Map<String, byte[]> wrappedKeys = getWrappedKeys(communicationHandler);
                            if (wrappedKeys == null) {
                                break;
                            }
                            enviarCopiasCifradasFicheiro(imagem, wrappedKeys, communicationHandler);

                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "RT":
                        if (commands.size() == 2) {
                            communicationHandler.enviarMensagem(commands);
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            communicationHandler.flush();
                            if (response.equals("OK")) {
                                String dados = receberTemperaturas(communicationHandler);
                                escreverParaFicheiro(dados, commands.get(1));
                            }
                        } else {
                            System.err.println("Formato inválido.");
                        }
                        break;

                    case "RI":
                        if (commands.size() == 3) {
                            communicationHandler.enviarMensagem(commands);
                            response = (String) communicationHandler.lerResposta();
                            System.out.println(response);
                            communicationHandler.flush();
                            if (response.equals("OK")) {
                                byte[] image = (byte[]) communicationHandler.lerResposta();
                                byte[] wrappedKey = (byte[]) communicationHandler.lerResposta();
                                receberImagens(image, wrappedKey, communicationHandler);
                            }

                        }else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    case "MYDOMAINS":
                        if (commands.size() == 1) {
                            communicationHandler.enviarMensagem(commands);
                            List<String> listaDominios = (List<String>) communicationHandler.lerResposta();
                            if (listaDominios.size() == 0) {
                                System.out.println("Este dispositivo ainda nao pertence a nenhum dominio.");
                                communicationHandler.flush();
                            }
                            for (String d : listaDominios) {
                                System.out.println(d);
                                communicationHandler.flush();
                            }
                        }else {
                            System.err.println("Formato inválido.");
                        }
                        break;
                    default:
                        System.err.println("Formato inválido.");
                        break;
                }
                System.out.print("COMANDO:");
            }
        }
    }

    private void escreverParaFicheiro(String dados, String dominio) {
        String fileName = "RT-" + dominio + ".txt";

        try {
            FileWriter writer = new FileWriter(fileName);
            writer.write(dados);
            writer.close();
            System.out.println("Dados escritos para o arquivo " + fileName + " com sucesso.");
        } catch (IOException e) {
            System.out.println("Ocorreu um erro ao escrever para o arquivo " + fileName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String receberTemperaturas(ComunicacaoHandler communicationHandler) {
        Map<String, byte[]> temperaturasCifradas = (Map<String, byte[]>) communicationHandler.lerResposta();
        byte[] wrappedKey = (byte[]) communicationHandler.lerResposta();

        Key sharedKey = getSharedKey(wrappedKey);
        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, byte[]> entry : temperaturasCifradas.entrySet()) {
            sb.append(entry.getKey()).append(":");
            // decifrar temperatura com sharedKey
            String temperatura = decriptar(entry.getValue(), sharedKey);
            sb.append(temperatura);
        }
        return sb.toString();
    }

    private void receberImagens(byte[] file, byte[] key, ComunicacaoHandler communicationHandler) {

        Key sharedKey = getSharedKey(key);
        Cipher decryptCipher = null;
        try {
            decryptCipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, sharedKey);
        } catch (InvalidKeyException e) {
            System.err.println("Não tem a password correta para decifrar imagem.");
        }
        try {
            byte[] decryptedData = decryptCipher.doFinal(file);
            String fileName = "imagemRecebida.jpg";
            File fileReceived = new File(fileName);

            try (FileOutputStream fos = new FileOutputStream(fileReceived)) {
                fos.write(decryptedData);
                System.out.println("Imagem recebida, foi guardada com o nome:" + fileName);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Failed to save image: ");
            }

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }

    private String decriptar(byte[] dados, Key sharedKey) {
        Cipher decryptCipher = null;
        try {
            decryptCipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, sharedKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        try {
            byte[] decryptedData = decryptCipher.doFinal(dados);
            return new String(decryptedData);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Faz unwrap da wrapped key recebida do servidor para obter a sharedKey
     * desse dominio
     *
     * @param wrappedKey a key que foi cifrada com chave publica do user
     * @return a chave do dominio
     */
    private Key getSharedKey(byte[] wrappedKey) {
        PrivateKey pk = getPrivateKeyUser();
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Error instancing cipher with RSA");
        }
        try {
            cipher.init(Cipher.UNWRAP_MODE, pk);
        } catch (InvalidKeyException e) {
            System.err.println("Invalid private key to access data");
        }
        try {
            return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            System.err.println("Error while using private key.");
        }
        return null;
    }

    private Map<String, byte[]> getWrappedKeys(ComunicacaoHandler communicationHandler) {
        try {
            Map<String, byte[]> chavesDominios = (Map<String, byte[]>) communicationHandler.lerResposta();
            return chavesDominios;
        } catch (Exception e) {
            System.err.println("Error while retriving domain keys from server.");
            return null;
        }
    }

    private void enviarCopiasCifradas(String temperatura, Map<String, byte[]> wrappedKeys, ComunicacaoHandler communicationHandler) {
        Map<String, byte[]> copiasTemperaturas = new HashMap<>();

        for (Map.Entry<String, byte[]> entry : wrappedKeys.entrySet()) {
            String dominio = entry.getKey();
            byte[] wrappedKey = entry.getValue();
            Key sharedKey = getSharedKey(wrappedKey);
            byte[] temperaturaCifrada = cifrarDados(sharedKey, temperatura);
            copiasTemperaturas.put(dominio, temperaturaCifrada);
        }
        communicationHandler.enviarMensagem(copiasTemperaturas);
    }

    private void enviarCopiasCifradasFicheiro(File imagem, Map<String, byte[]> wrappedKeys, ComunicacaoHandler communicationHandler) {

        Map<String, byte[]> copiasImagem = new HashMap<>();

        for (Map.Entry<String, byte[]> entry : wrappedKeys.entrySet()) {
            String dominio = entry.getKey();
            byte[] wrappedKey = entry.getValue();
            Key sharedKey = getSharedKey(wrappedKey);
            byte[] imagemCifrada = cifrarFicheiros(sharedKey, imagem);
            copiasImagem.put(dominio, imagemCifrada);
        }
        communicationHandler.enviarMensagem(copiasImagem);
    }

    private byte[] cifrarDados(Key sharedKey, String dados) {
        Cipher c = null;
        try {
            c = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Erro no algoritmo a cifrar dados com chave dominio.");
            return null;
        }
        try {
            c.init(Cipher.ENCRYPT_MODE, sharedKey);
            return c.doFinal(dados.getBytes());

        } catch (InvalidKeyException e) {
            System.err.println("Erro a cifrar dados com a chave do dominio - chave de dominio inválida.");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private byte[] cifrarFicheiros(Key sharedKey, File file) {
        Cipher c = null;
        try {
            c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, sharedKey);

            byte[] fileContent = Files.readAllBytes(file.toPath());

            return c.doFinal(fileContent);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Erro no algoritmo a cifrar dados com chave dominio.");
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            System.err.println("Erro a cifrar dados com a chave do dominio - chave de dominio inv�lida.");
            e.printStackTrace();
        }
        return null;
    }

    private boolean isTemperature(String value) {
        String temperatureRegex = "^-?\\d+(\\.\\d+)?$";
        return value.matches(temperatureRegex);
    }

    private PublicKey retrieveUserPublicKey(KeyStore truststore, String userId) {
        try {
            Certificate userCert = truststore.getCertificate(userId);
            if (userCert != null) {
                return userCert.getPublicKey();
            } else {
                System.err.println("Public key not found for user: " + userId);
                return null;
            }
        } catch (KeyStoreException e) {
            System.err.println("Error retrieving public key for user: " + e.getMessage());
            return null;
        }
    }

    private byte[] cifrarComChavePublicaNovoUser(SecretKey chaveDominio, String newuser, String dominio) {
        PublicKey newUserPublicKey = retrieveUserPublicKey(truststore, newuser);
        if (newUserPublicKey == null || chaveDominio == null) {
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.WRAP_MODE, newUserPublicKey);
            return cipher.wrap(chaveDominio);
        } catch (Exception e) {
            System.err.println("Não foi possivel adicionar cliente, verifique se chave publica do user que tenta adicionar está na truststore.");
            return null;
        }
    }

    private void salvarParametrosDominio(String dominioName, byte[] salt, int iteracoes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(this.userId + "_parametros_dominio.txt", true))) {
            // Convert byte array to Base64 string
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            // Write the parameters to the file
            writer.write(dominioName + ", " + saltBase64 + ", " + iteracoes);
            writer.newLine();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey gerarPasswordDominio(String dominio, String passwordDominio) {
        byte[] salt = saltMap.get(dominio);
        Integer iterations = iterationsMap.get(dominio);

        if (salt == null || iterations == null) {
            salt = generateSalt();
            iterations = generateIterations();
            saltMap.put(dominio, salt);
            iterationsMap.put(dominio, iterations);
            System.out.println("Generated new domain parameters for domain: " + dominio);
            salvarParametrosDominio(dominio, salt, iterations);
        }
        try {
            /**
             * Criaçao chave dominio cifrada
             */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordDominio.toCharArray(), salt, iterations, 128);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (Exception e) {
            System.err.println("Erro ao gerar password do dominio");
            return null;
        }
    }

    private int generateIterations() {
        return (int) (Math.random() * 100) + 20;
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[8];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (Math.random() * 256 - 128);
        }
        return salt;
    }
}
