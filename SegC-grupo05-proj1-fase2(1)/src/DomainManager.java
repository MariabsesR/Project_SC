package src;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
public class DomainManager {
    private final Set<Domain> domains;

    private final FilesHandler filesHandler;

    public DomainManager(FilesHandler filesHandler) {
        this.filesHandler = filesHandler;
        this.domains = filesHandler.loadDomains();
    }

    /**
     * Encontra um dado dominio
     *
     * @param domainName o nome do dominio a encontrar
     * @return retorna o dominio, se nao encontrar retorna null
     */
    public Domain findDomain(String domainName) {
        for (Domain domain : domains) {
            if (domain.getName().equals(domainName)) {
                return domain;
            }
        }
        return null;
    }

    /**
     * Cria um novo dominio
     *
     * @param nomeDominio o nome do novo dominio
     * @param criador     o nome do criador do dominio
     */
    public boolean createDomain(String nomeDominio, String criador) {
        return domains.add(new Domain(nomeDominio, criador));
    }

    /**
     * Verifica se o userId dado pertence ao owner do dominio
     *
     * @param userId userId a verificar
     * @param domain o nome do dominio
     * @return true se user eh criador do dominio, senao false
     */
    public boolean verificarOwner(String userId, String domain) {
        return findDomain(domain).getCriador().equals(userId);
    }

    /**
     * Faz update do ficheiro que guarda os dominios no servidor
     * persistencia
     *
     * @return true se foi possivel fazer o update, senao false
     */
    public boolean updateFileDomains() {
        return filesHandler.updateFileDomains(domains);
    }

    /**
     * Adiciona um novo utilizador ao dominio
     *
     * @param newUser             o userId do novo utilizador
     * @param domain              o nome do dominio
     * @param chaveDominioCifrada
     */
    public boolean addNewUser(String newUser, String domain, byte[] chaveDominioCifrada) {
        boolean ret = false;
        Domain d = findDomain(domain);
        if (d != null && d.addUser(newUser)) {
            d.addChaveDominio(newUser, chaveDominioCifrada);
            ret = true;
        }
        filesHandler.updateFileDomains(domains);
        return ret;
    }

    public void addNewDevice(String userId, int device, Domain domain) {
        domain.addDevice(userId, device);
    }

    public Map<String, byte[]> getTemperaturas(String dominio) {
        Domain domain = findDomain(dominio);
        if (domain == null) return null;
        return domain.getTemperaturas();
    }

    public boolean belongsToDomain(String domain, String newUser) {
        Domain d = findDomain(domain);
        if (d != null) {
            return d.contains(newUser);
        }
        return false;
    }

    public Map<String, byte[]> getChavesDominios(String userId, int deviceId) {
        List<String> domainsDeviceIsIn = findDeviceDomains(userId, deviceId);
        Map<String, byte[]> chavesDominios = new HashMap<>();
        for (String domainName : domainsDeviceIsIn) {
            Domain n = findDomain(domainName);
            if (n != null) {
                byte[] chave = n.getWrappedKey(userId);
                if (chave != null) {
                    chavesDominios.put(domainName, chave);
                }

            }
        }
        return chavesDominios;
    }

    protected List<String> findDeviceDomains(String userId, int deviceId) {
        List<String> domainsDeviceIsIn = new ArrayList<>();
        for (Domain domain : domains) {
            if (domain.isDeviceInDomain(userId+":"+deviceId)) {
                domainsDeviceIsIn.add(domain.getName());
            }
        }
        return domainsDeviceIsIn;
    }

    public void guardarTemperaturasCifradas(Map<String, byte[]> temperaturasCifradas, String userId, int deviceId) {
        for (Map.Entry<String, byte[]> entry : temperaturasCifradas.entrySet()) {
            String dominio = entry.getKey();
            byte[] temperaturaCifrada = entry.getValue();
            Domain dom = findDomain(dominio);
            dom.registarTemperatura(userId,deviceId,temperaturaCifrada);
            filesHandler.updateFileDomains(domains);
        }
    }

    public void guardarImagensCifradas(Map<String, byte[]> imagensCifradas, String userId, int deviceId) {

        for (Map.Entry<String, byte[]> entry : imagensCifradas.entrySet()) {
            String dominio = entry.getKey();
            byte[] imagemCifrada = entry.getValue();
            File folder = filesHandler.getPastaImagens();
            Domain dom = findDomain(dominio);
            if (dom != null) {
                String dev = dom.getDevice(userId, deviceId);
                if (dev != null) {
                    String fileName = userId + "-" + deviceId + "-" + dominio + ".cif";
                    File file = new File(folder, fileName);

                    try (FileOutputStream fos = new FileOutputStream(file)) {
                        fos.write(imagemCifrada);
                        System.out.println("Encrypted image saved: " + file.getAbsolutePath());
                    } catch (IOException e) {
                        e.printStackTrace();
                        System.err.println("Failed to save encrypted image: " + e.getMessage());
                    }
                }
            }

        }
    }

    public byte[] getWrappedKey(String domain, String userId) {
        Domain d = findDomain(domain);
        return d.getWrappedKey(userId);
    }

    public Set<Domain> getDomains() {
        return domains;
    }

    public Domain getFirstCommonDomain(String userId, String userWanted, int deviceWanted) {
        for(Domain d : domains){
            if(d.isDeviceInDomain(userWanted+":"+deviceWanted) && d.contains(userId)){
                return d;
            }
        }
        return null;
    }
}
