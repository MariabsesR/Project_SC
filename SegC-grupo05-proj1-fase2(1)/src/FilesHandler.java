package src;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.spec.KeySpec;
import java.util.*;

/**
 * Esta classe é responsável por criar e fazer update dos ficheiros que
 * presentes no IoTServer
 */
public class FilesHandler {
    private static final String APLICACAO_FILE_PATH = "aplicacao.txt";
    private final File ficheiroUtilizadores;
    private final File pastaDominios;
    private final File ficheiroDispositivos;

    private final File ficheiroHmacs;
    private final String passwordCifra;
    private final File pastaCertificados;
    private final File pastaImagens;
    private final PrivateKey pk;

    private final PublicKey publicKey;

    private final Map<String, byte[]> hmacs;

    /**
     * Construtor da classe FilesHandler Inicializa os ficheiros e pastas
     * necessários.
     */
    public FilesHandler(String passwordCifra, PrivateKey pk, PublicKey publicKey) {
        this.pk = pk;
        this.publicKey = publicKey;
        this.passwordCifra = passwordCifra;
        this.pastaImagens = new File("imagens");
        this.pastaDominios = new File("dominios");
        this.pastaCertificados = new File("certificados-servidor");
        this.ficheiroUtilizadores = new File("utilizadores.cif");
        this.ficheiroDispositivos = new File("dispositivos.txt");
        this.ficheiroHmacs = new File("hmacs.txt");
        this.hmacs = getHmacsFromFile();
        criarFicheiros();
    }

    public File getPastaImagens() {
        return pastaImagens;
    }

    private void criarFicheiros() {
        criarFicheiroHmacs(ficheiroHmacs);
        criarPasta(pastaCertificados);
        criarPasta(pastaImagens);
        criarPasta(pastaDominios);
        criarFicheiro(ficheiroUtilizadores);
        criarFicheiro(ficheiroDispositivos);
    }

    private void criarFicheiroHmacs(File ficheiroHmacs) {
        if (!ficheiroHmacs.exists()) {
            try {
                ficheiroHmacs.createNewFile();
                criarHmac(APLICACAO_FILE_PATH);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Cria uma nova pasta se esta pasta ainda nao existe
     *
     * @param pasta a pasta a criar
     */
    private void criarPasta(File pasta) {
        if (!pasta.exists()) {
            pasta.mkdir();
        }
    }

    /**
     * Cria ficheiro file se não existir ainda
     *
     * @param file o ficheiro a criar
     */
    private void criarFicheiro(File file) {
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void saveHmacsToFile() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(ficheiroHmacs))) {
            oos.writeObject(hmacs);
            System.out.println("Ficheiro hmacs.txt foi atualizado : " + ficheiroHmacs.getName());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Map<String, byte[]> getHmacsFromFile() {
        if (ficheiroHmacs.length() == 0) return new HashMap<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(ficheiroHmacs))) {
            Map<String, byte[]> map = (Map<String, byte[]>) ois.readObject();
            System.out.println("HMACS foram recuperados do ficheiro: " + ficheiroHmacs.getName());
            return map;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return new HashMap<>();
    }

    private static byte[] decryptData(byte[] encryptedData, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(encryptedData);
    }

    protected Map<String, String> loadUtilizadores() {
        Map<String, String> utilizadores;
        if (ficheiroUtilizadores.length() == 0) return new HashMap<>();
        try {
            byte[] salt = new byte[16];
            byte[] ivBytes = new byte[16];
            try (FileInputStream fis = new FileInputStream(ficheiroUtilizadores)) {
                fis.read(salt);
                fis.read(ivBytes);
            }

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordCifra.toCharArray(), salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            byte[] encryptedData;
            try (FileInputStream fis = new FileInputStream(ficheiroUtilizadores)) {
                // Skip salt and IV bytes
                fis.skip(32); // 16 bytes (salt) + 16 bytes (IV)
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                encryptedData = baos.toByteArray();
            }
            byte[] decryptedData = decryptData(encryptedData, secretKey, iv);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedData))) {
                utilizadores = (Map<String, String>) ois.readObject();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return utilizadores;
    }

    /**
     * Faz update do ficheiro que guarda os dominios no servidor persistencia
     *
     * @param domains Conjunto de domínios a serem escritos no arquivo
     * @return true se foi possível fazer o update, senão false
     */
    public boolean updateFileDomains(Set<Domain> domains) {
        for (Domain d : domains) {
            String fileName = pastaDominios.getPath() + FileSystems.getDefault().getSeparator() + d.getName() + ".txt";
            try (PrintWriter writer = new PrintWriter(new FileWriter(fileName, false))) {
                writer.println(d);
                writer.close();
                criarHmac(fileName);
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }

    /**
     * Remove o conteudo de um dado ficheiro
     *
     * @param ficheiro o ficheiro a limpar
     */
    private void cleanFile(File ficheiro) {
        try {
            FileWriter fileWriter = new FileWriter(ficheiro, false);
            fileWriter.write(""); // para limpar conteudo atual do ficheiro
            fileWriter.close();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

    }

    /**
     * Faz update e cifra o ficheiro dos utilizadores
     *
     * @param utilizadores
     * @return
     */
    protected boolean cifrarUsersFile(Map<String, String> utilizadores) {
        try {
            cleanFile(this.ficheiroUtilizadores);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(utilizadores);
            byte[] data = baos.toByteArray();

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordCifra.toCharArray(), salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encryptedData = cipher.doFinal(data);
            try (FileOutputStream fos = new FileOutputStream(ficheiroUtilizadores.getPath())) {
                fos.write(salt);
                fos.write(ivBytes);
                fos.write(encryptedData);
            }
            System.out.println("File encrypted successfully.");
        } catch (Exception e) {
            System.err.println("Error encrypting file: " + e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Escreve informacao que esta nas estruturas de dados que guardam
     * informacao sobre os dispositivos para os ficheiros do servidor.
     *
     * @param devices o conjunto de todos os dispositivos
     * @return true se foi possivel fazer update, senao false
     */
    protected boolean updateDevicesFile(Set<String> devices) {
        cleanFile(this.ficheiroDispositivos);
        try (FileOutputStream fileOutputStream = new FileOutputStream(this.ficheiroDispositivos); ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
            objectOutputStream.writeObject(devices);
            criarHmac(ficheiroDispositivos.getPath());
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Recupera informacao sobre os dispositivos que esta guardada no servidor e
     * inicializa estrutura de dados dos dispositivos
     *
     * @return o mapa dos dispositivos
     */
    public Set<String> loadDevices() {
        Set<String> devices = new HashSet<>();
        if(!verifyHmac(ficheiroDispositivos.getPath())){
            return devices;
        }
        if(ficheiroDispositivos.length() == 0) return devices;
        try (FileInputStream fileInputStream = new FileInputStream(ficheiroDispositivos);
             ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {

            Object obj = objectInputStream.readObject();
            if (obj instanceof Set) {
                devices = (Set<String>) obj;
            }

        } catch (ClassNotFoundException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return devices;
    }

/**
 * Recupera informacao sobre os dominios que esta guardada no servidor e
 * inicializa estrutura de dados do dominio
 *
 * @return o conjunto de todos os dominios
 */
public Set<Domain> loadDomains() {
    Set<Domain> domains = new HashSet<>();
    File[] domainFiles = pastaDominios.listFiles();

    if (domainFiles != null) {
        for (File file : domainFiles) {
            if (file.isFile()) {
                if (!verifyHmac(file.getPath())) {
                    break;
                }
                try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                    String fileName = file.getName();
                    String domainName = fileName.substring(0, fileName.lastIndexOf('.'));
                    String line;
                    String creator = null;
                    Set<String> users = new HashSet<>();
                    Set<String> devices = new HashSet<>();
                    Map<String, byte[]> temperatures = new HashMap<>();
                    Map<String, byte[]> domainKeys = new HashMap<>();

                    while ((line = br.readLine()) != null) {
                        String[] lineParts = line.split("=/VALUE/");
                        if (lineParts.length == 2) {
                            String key = lineParts[0];
                            String value = lineParts[1];

                            switch (key) {
                                case "CREATOR":
                                    creator = value;
                                    break;
                                case "USERS":
                                    users.addAll(Arrays.asList(value.split(",")));
                                    break;
                                case "DEVICES":
                                    devices.addAll(Arrays.asList(value.split(",")));
                                    break;
                                case "TEMPERATURAS":
                                    String[] tempParts = value.split(",");
                                    for (int i = 0; i < tempParts.length; i += 2) {
                                        temperatures.put(tempParts[i], Base64.getDecoder().decode(tempParts[i + 1]));
                                    }
                                    break;
                                case "CHAVESDOMINIO":
                                    String[] keyParts = value.split(",");
                                    for (int i = 0; i < keyParts.length; i += 2) {
                                        domainKeys.put(keyParts[i], Base64.getDecoder().decode(keyParts[i + 1]));
                                    }
                                    break;
                            }
                        }
                        if (creator != null) {
                            Domain domain = new Domain(domainName, creator);
                            domain.setUtilizadores(users);
                            domain.setDevices(devices);
                            domain.setTemperaturas(temperatures);
                            domain.setChavesDominio(domainKeys);
                            domains.add(domain);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    return domains;
}

private void criarHmac(String filePath) {
    try {
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(pk);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        hmacs.put(filePath, digitalSignature);
        saveHmacsToFile();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
        System.err.println("Não foi possivel assinar o ficheiro: " + filePath);
    }
}

protected boolean verifyHmac(String filePath) {
    try {
        if (hmacs.containsKey(filePath)) {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            File file = new File(filePath);
            byte[] fileData = Files.readAllBytes(file.toPath());
            signature.update(fileData);
            byte[] existingSignature = hmacs.get(filePath);
            boolean signatureValid = signature.verify(existingSignature);

            if (signatureValid) {
                System.out.println("Verificacao HMAC bem sucedida: " + filePath);
            } else {
                System.out.println("Verificacao HMAC falhou para ficheiro: " + filePath);
            }
            return signatureValid;
        } else {
            System.out.println("Ainda nao existe hmac para ficheiro: " + filePath);
            return true;
        }
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
        e.printStackTrace();
    }
    return false;
}

/**
 * Guarda o certificado recebido do utilizador na pasta com certificados
 * dentro do servidor
 *
 * @param certificate o certificado do utilizador local recebido
 * @param userId      o (endereço de email do) utilizador local
 * @return o path para o certificado
 */
public String guardarCertificado(Certificate certificate, String userId) {
    String filePath = pastaCertificados.getPath() + File.separator + userId + ".cer";
    try (FileOutputStream fos = new FileOutputStream(filePath)) {
        fos.write(certificate.getEncoded());
        System.out.println("Certificate saved to " + filePath);
    } catch (IOException | CertificateEncodingException e) {
        e.printStackTrace();
        return null;
    }
    return filePath;
}

public byte[] getEncryptedImage(String userId, int deviceId, String domain) {
    File folder = getPastaImagens();
    String fileName = userId + "-" + deviceId + "-" + domain + ".cif";
    File file = new File(folder, fileName);

    if (file.exists()) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] imageData = new byte[(int) file.length()];
            fis.read(imageData);
            return imageData;
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Failed to read encrypted image: " + e.getMessage());
        }
    } else {
        System.err.println("Image file not found: " + file.getAbsolutePath());
    }

    return null;
}

}
