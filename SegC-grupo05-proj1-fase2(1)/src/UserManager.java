package src;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;

/**
 * A classe UserManager é responsável por gerir os utilizadores do sistema.
 */
public class UserManager {
    private final Set<String> devices;
    private Map<String,String> utilizadores;
    private final Set<String> devicesLoggedIn;
    private final FilesHandler filesHandler;

    /**
     * Construtor da classe UserManager.
     *
     * @param filesHandler classe que contem todos os ficheiros a ser acedidos
     */
    public UserManager(FilesHandler filesHandler) {
        this.filesHandler = filesHandler;
        this.utilizadores = this.filesHandler.loadUtilizadores();
        this.devices = this.filesHandler.loadDevices();
        filesHandler.loadDomains();
        this.devicesLoggedIn = new HashSet<>();

    }
    /**
     * Regista o email de um novo user no servidor
     *
     * @param userId       o userId a registar
     * @param pathCertificate o file path para o certificado do user
     */
    public boolean registarUser(String userId, String pathCertificate) {
        utilizadores.put(userId,pathCertificate);
        return filesHandler.cifrarUsersFile(utilizadores);
    }
    /**
     * Verifica se um dado device já está a utilizar o servidor
     * @param userId userId
     * @param deviceId deviceId
     * @return true se device ja está a usar server, senao falso
     */

    public boolean isDeviceLoggedIn(String userId, int deviceId) {
        return devicesLoggedIn.contains(userId+":"+deviceId);
    }

    /**
     * Adiciona um novo device ao servidor
     * @param userId o user do device
     * @param deviceId o id do device
     */
    public void addDispositivoLoggedIn(String userId, int deviceId) {
        devicesLoggedIn.add(userId+":"+deviceId);
        devices.add(userId+":"+deviceId);
        filesHandler.updateDevicesFile(devices);
    }

    public void desconectarDispositivo(String userId, int deviceId) {
        devicesLoggedIn.remove(userId+":"+deviceId);
    }

    public boolean isUser(String newUser) {
        return utilizadores.containsKey(newUser);
    }

    public PublicKey getPublicKey(String userId) {
        String pathCertificado = utilizadores.get(userId);
        if(pathCertificado == null) return null;

        try (FileInputStream fis = new FileInputStream(pathCertificado)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certFactory.generateCertificate(fis);
            return certificate.getPublicKey();
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }

    }

    public String getPathCertificate(String userId) {
        return utilizadores.get(userId);
    
    }

	public Map<String, String> getUtilizadores() {
		return utilizadores;
	}
    
	public boolean checkIfUserHasDevice(String userId,int deviceUser) {
		return devices.contains(userId+":"+deviceUser);
	}
    
    
}



