package src;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Classe ServerManager gere o servidor
 * Guarda estruturas de dados
 * Encaminha update dos ficheiros do server para filehandler
 * Gere concorrencia
 * Faz load da keystore do servidor
 */
public class ServerManager {
    private final KeyStore serverKeystore;
    private final String keystorePath;
    private final String passwordKeystore;
    private final String apikey;
    private final ReentrantReadWriteLock readWriteLock;
    private final DomainManager domainManager;
    private final UserManager userManager;

    private final FilesHandler filesHandler;

    /**
     * Cria um novo ServerManager atraves dos
     * argumentos dados ao programa IoTServer
     *
     * @param args os argumentos do programa IoTServer
     * @throws IOException
     */
    public ServerManager(String[] args) throws IOException {

        // separacao de argumentos devido ao porto que é opcional
        String passwordCifra;
        if (args.length > 4) {
            passwordCifra = args[1];
            this.keystorePath = args[2];
            this.passwordKeystore = args[3];
        } else {
            passwordCifra = args[0];
            this.keystorePath = args[1];
            this.passwordKeystore = args[2];
        }

        this.apikey = args[args.length - 1];
        this.serverKeystore = criarKeystore(this.keystorePath, passwordKeystore);
        PrivateKey pk = null;
        try {
            pk = (PrivateKey) serverKeystore.getKey("server", passwordKeystore.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("Erro ao tentar aceder á chave privada do servidor!");
            System.exit(1);
        }
        PublicKey publicKey = null;
        try {
            KeyStore serverKeystore = criarKeystore(keystorePath, passwordKeystore);
            Certificate cert = serverKeystore.getCertificate("server");
            publicKey = cert.getPublicKey();
        } catch (KeyStoreException e) {
            System.err.println("Erro ao tentar aceder à chave pública do servidor!");
            System.exit(1);
        }

        this.readWriteLock = new ReentrantReadWriteLock(true);
        this.filesHandler = new FilesHandler(passwordCifra, pk, publicKey);
        this.userManager = new UserManager(filesHandler);
        this.domainManager = new DomainManager(filesHandler);
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    /**
     * Faz load da KeyStore do servidor
     *
     * @param keystorePath     a path para a keystore do servidor
     * @param passwordKeystore a password da keystore
     * @return a keystore do servidor ou null em caso de erro
     */
    private KeyStore criarKeystore(String keystorePath, String passwordKeystore) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("jceks");
            FileInputStream fis = new FileInputStream(keystorePath);
            ks.load(fis, passwordKeystore.toCharArray());

        } catch (FileNotFoundException | KeyStoreException e) {
            System.out.println("Nao conseguiu encontrar keystore");
        } catch (CertificateException e) {
            System.out.println("Nao conseguiu carregar algum dos certificados na keystore");
        } catch (IOException e) {
            System.out.println("Password incorreta ou inexistente para a keystore");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Nao consegue carregar keystore");
        }
        return ks;
    }

    /**
     * Retorna a keystore do server
     *
     * @return a keystore do server
     */
    public KeyStore getKeystore() {
        return serverKeystore;
    }

    /**
     * Retorna a password da keystore do servidor
     *
     * @return a password da keystore do servidor
     */
    public String getPasswordKeystore() {
        return passwordKeystore;
    }

    /**
     * Retorna a 2FA-APIKEY
     *
     * @return a 2FA-APIKEY
     */
    public String getApikey() {
        return apikey;
    }

    /**
     * Regista o email de um novo utilizador no servidor
     *
     * @param userId          o userId a registar
     * @param pathCertificado o path para o certificado do utilizador
     */
    public boolean registarUser(String userId, String pathCertificado) {
        readWriteLock.writeLock().lock();
        try {
            return userManager.registarUser(userId, pathCertificado);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Verifica se um dado device já está a utilizar o servidor
     *
     * @param userId   userId o id do user a verificar
     * @param deviceId deviceId o id do dispositivo do user a verificar
     * @return true se o dispositivo está a usar server, senao falso
     */
    public boolean isDeviceLoggedIn(String userId, int deviceId) {
        readWriteLock.readLock().lock();
        try {
            return userManager.isDeviceLoggedIn(userId, deviceId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Adiciona um novo dispositivo ao servidor
     *
     * @param userId   o user do dispositivo
     * @param deviceId o id do dispositivo
     */
    public void addDispositivoLoggedIn(String userId, int deviceId) {
        readWriteLock.writeLock().lock();
        try {
            userManager.addDispositivoLoggedIn(userId, deviceId);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Retorna o path para o certificado de um dado utilizador
     *
     * @param userId o id do utilizador para obter o certificado
     * @return o path para o ficheiro do certificado do utilizador
     */
    public String getPathCertificate(String userId) {
        return userManager.getPathCertificate(userId);
    }

    /**
     * Desconecta um dado dispositivo
     *
     * @param userId   o user do dispositivo
     * @param deviceId o id do dispositivo
     */
    public void desconectarDispositivo(String userId, int deviceId) {
        readWriteLock.writeLock().lock();
        try {
            userManager.desconectarDispositivo(userId, deviceId);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Cria um novo dominio e faz update do ficheiro
     * que guarda a informacao dos dominios no servidor
     * para que seja persistente
     *
     * @param nomeDominio o nome do novo dominio
     * @param owner       o dono do dominio
     * @return True se foi possivel criar o dominio, senao False
     */
    public boolean createDomain(String nomeDominio, String owner) {
        readWriteLock.writeLock().lock();
        try {
            boolean isCreated = domainManager.createDomain(nomeDominio, owner);
            domainManager.updateFileDomains();
            return isCreated;
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Verifica se um userId eh o dono de um dado dominio
     *
     * @param userId o userId a verificar
     * @param domain o dominio a verificar
     * @return True se o userId corresponder ao dono do dominio dado,
     * senao False
     */
    public boolean verificarOwner(String userId, String domain) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.verificarOwner(userId, domain);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Verifica se o nome do dominio corresponde
     * a um dominio no servidor
     *
     * @param nomeDominio o nome do dominio a verificar
     * @return True se o nome do dominio corresponde a um dominio
     * que existe no servidor
     */
    public boolean isDomain(String nomeDominio) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.findDomain(nomeDominio) != null;
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Verifica se um dado user id
     * corresponde a um user que existe no servidor
     *
     * @param userId o user id a verificar
     * @return True se o userId existe no servidor, senao False
     */
    public boolean isUser(String userId) {
        readWriteLock.readLock().lock();
        try {
            return userManager.isUser(userId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Verifica se um user id pertence a um dado dominio
     *
     * @param domainName o nome do dominio a verificar
     * @param userId     o id do utilizador a verificar
     * @return True se o utilizador pertence ao dominio dado
     */
    public boolean belongsToDomain(String domainName, String userId) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.belongsToDomain(domainName, userId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Verifica se um dado dispositivo pertence a um dominio
     *
     * @param domainName o nome do dominio a verificar
     * @param deviceId   o numero do id do dispositivo a verificar
     * @param user       o user id do dispositivo a verificar
     * @return true se o dispositivo pertence ao dominio, senao false
     * @requires {@code domainsManager != null && isDomain(domainName}
     */
    public boolean DeviceIsInDomain(String domainName, int deviceId, String user) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.findDomain(domainName).isDeviceInDomain(user + ":" + deviceId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Adiciona um novo dispositivo ao dominio e faz update
     * do ficheiro dos dominios
     *
     * @param domainName o nome do dominio
     * @param userId     o user id do dispositivo a adicionar
     * @param deviceId   o id do dispositivo a adicionar
     */
    public void addDeviceToDomain(String domainName, String userId, int deviceId) {
        readWriteLock.writeLock().lock();
        try {
            Domain d = domainManager.findDomain(domainName);
            if (d != null) {
                domainManager.addNewDevice(userId, deviceId, d);
            }
            domainManager.updateFileDomains();
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Adiciona um novo user ao dominio
     *
     * @param newUser    o id do user a adicionar ao dominio
     * @param domainName o nome do dominio
     * @param wrappedKey a chave do dominio cifrada com
     *                   a chave publica do novo utilizador
     * @return true se foi possivel adicionar user ao dominio, senao false
     */
    public boolean addNewUserToDomain(String newUser, String domainName, byte[] wrappedKey) {
        readWriteLock.writeLock().lock();
        try {
            return domainManager.addNewUser(newUser, domainName, wrappedKey);
        } finally {
            readWriteLock.writeLock().unlock();
        }

    }

    /**
     * Obtem a chave publica de um dado utilizador
     *
     * @param userId o id do utilizador
     * @return a chave publica do utilizador se encontrar, senao null
     */
    public PublicKey getPublicKey(String userId) {
        readWriteLock.readLock().lock();
        try {
            return userManager.getPublicKey(userId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Retorna todos o id dos dispositivos que pertencem
     * a um dado dominio e as temperaturas destes
     *
     * @param dominio o dominio ao qual queremos obter as temperaturas
     * @return um mapa com o id dos dispositivos desse dominio e as suas
     * temperaturas associadas
     */
    public Map<String, byte[]> getDeviceTemperatures(String dominio) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.getTemperaturas(dominio);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Retorna todas as chaves de dominio que foram cifradas com
     * a chave publica desse utilizador
     *
     * @param userId   o id do utilizador
     * @param deviceId o id do dispositivo
     * @return um mapa com todas as wrapped keys desse utilizador
     * o nome dos dominios e a chave de dominio cifrada com a
     * chave publica desse utilizador
     */
    public Map<String, byte[]> getDomainWrappedKeys(String userId, int deviceId) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.getChavesDominios(userId, deviceId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Guarda as temperaturas cifradas com a chave de cada dominio
     * recebidas do IoTDevice
     *
     * @param temperaturasCifradas o dominio e as temperatura cifrada
     *                             para esse dominio
     * @param userId               o id do utilizador
     * @param deviceId             o id do dispositivo
     */
    public void guardarTemperaturasCifradas(Map<String, byte[]> temperaturasCifradas, String userId, int deviceId) {
        readWriteLock.writeLock().lock();
        try {
            domainManager.guardarTemperaturasCifradas(temperaturasCifradas, userId, deviceId);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Guarda as imagens cifradas recebidas do utilizadorna pasta Imagens
     *
     * @param imagemsCifradas imagens cifradas pelo utilizador
     * @param userId          Id do utilizador
     * @param deviceId        device do utilizador
     */

    public void guardarImagemsCifrada(Map<String, byte[]> imagemsCifradas, String userId, int deviceId) {
        readWriteLock.writeLock().lock();
        try {
            domainManager.guardarImagensCifradas(imagemsCifradas, userId, deviceId);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    /**
     * Retorna a wrappedKey associada de um dado utilizador
     * no dado dominio
     *
     * @param domain o dominio
     * @param userId o id do utilizador a quem pertence a wrappedKey
     * @return a wrapped key (chave do dominio cifrada com a chave
     * publica desse utilizador)
     */
    public byte[] getWrappedKey(String domain, String userId) {
        readWriteLock.readLock().lock();
        try {
        return domainManager.getWrappedKey(domain, userId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Retorna uma lista com o nome dos dominios que conteem
     * o dispositivo associado com o dado userId e deviceId
     *
     * @param userId   o id do utilizador
     * @param deviceId o id do dispositivo
     * @return retorna a lista com os nomes dos dominios ou null
     */
    public List<String> getDeviceDomains(String userId, int deviceId) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.findDeviceDomains(userId, deviceId);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    /**
     * Encaminha pedido de guardar o certificado de um dado user
     * para o fileshandler
     *
     * @param certificate o certificado a guardar
     * @param userId      o email do utilizador
     * @return o path para o certificado guardado
     */
    public String guardarCertificado(Certificate certificate, String userId) {
        readWriteLock.writeLock().lock();
        try {
            return filesHandler.guardarCertificado(certificate, userId);
        } finally {
            readWriteLock.writeLock().unlock();
        }
    }

    public byte[] getImagem(String userId, int deviceId, String domain) {
        if (domain == null) return null;
        readWriteLock.readLock().lock();
        try {
            return filesHandler.getEncryptedImage(userId, deviceId, domain);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    public Map<String, String> getUtilizadores() {
        readWriteLock.readLock().lock();
        try {
            return userManager.getUtilizadores();
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    public boolean checkIfUserHasDevice(String userId, int deviceUser) {
        readWriteLock.readLock().lock();
        try {
        return userManager.checkIfUserHasDevice(userId, deviceUser);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    public Domain getFirstCommonDomain(String userId, String userWanted, int deviceWanted) {
        readWriteLock.readLock().lock();
        try {
            return domainManager.getFirstCommonDomain(userId, userWanted, deviceWanted);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }

    public boolean verificarHmac(String aplicacaoFilePath) {
        readWriteLock.readLock().lock();
        try {
            return filesHandler.verifyHmac(aplicacaoFilePath);
        } finally {
            readWriteLock.readLock().unlock();
        }
    }
}
