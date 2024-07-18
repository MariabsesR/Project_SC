package src;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.*;

/**
 * A classe src.Domain representa um domínio dentro de src.IoTServer
 */
public class Domain implements Serializable {

    private final String name;

    private Set<String> devices;    // Conjunto de dispositivos associados ao domínio
    private final String criador;
    private Set<String> utilizadores;

    private Map<String, byte[]> temperaturas;

    // Mapa com userId e a chave do dominio wrapped com public key desse user
    private Map<String, byte[]> chavesDominio;

    /**
     * Constrói um novo objeto src.Domain com o nome especificado e o conjunto de dispositivos.
     *
     * @param name o nome do domínio
     */
    public Domain(String name, String criador) {
        this.name = name;
        this.criador = criador;
        this.devices = new HashSet<>();
        this.utilizadores = new HashSet<>();
        this.chavesDominio = new HashMap<>();
        this.temperaturas = new HashMap<>();
    }

    /**
     * Obtém o nome do domínio.
     *
     * @return o nome do domínio
     */
    public String getName() {
        return name;
    }

    /**
     * Obtém o nome do domínio.
     *
     * @return o nome do domínio
     */
    public String getCriador() {
        return criador;
    }

    /**
     * Verifica se este objeto src.Domain é igual a outro objeto.
     *
     * @param o objeto a ser comparado
     * @return true se os objetos forem iguais, false caso contrário
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Domain domain = (Domain) o;
        return Objects.equals(name, domain.name);
    }

    /**
     * Retorna o código de hash para este objeto src.Domain.
     *
     * @return o código de hash do objeto
     */
    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    public boolean addUser(String newUser) {
        return utilizadores.add(newUser);
    }

    /**
     * Retorna o dispositivo com o ID de usuário e o ID do dispositivo dados.
     *
     * @param user     o ID do user
     * @param deviceId o ID do dispositivo
     * @return o dispositivo, se encontrado, ou null se não encontrado
     */
    public String getDevice(String user, int deviceId) {
        for (String d : devices) {
            if (d.equals(user+":"+deviceId)) {
                return d;
            }
        }
        return null;
    }

    protected void addDevice(String userId, int deviceId) {
        devices.add(userId+":"+deviceId);
    }

    public boolean isDeviceInDomain(String device) {
        return devices.contains(device);
    }

    public Map<String, byte[]> getTemperaturas() {
        return temperaturas;
    }

    public void addChaveDominio(String newUser, byte[] chaveDominioCifrada) {
        chavesDominio.put(newUser, chaveDominioCifrada);
    }

    public boolean contains(String newUser) {
        return utilizadores.contains(newUser);
    }

    public byte[] getWrappedKey(String userId) {
        return chavesDominio.get(userId);
    }

    /**
     * Adiciona uma nova temperatura de um device ao dominio
     * @param userId o user id associado ao device
     * @param deviceId o device id do user do device
     * @param temperaturaCifrada a temperatura cifrada com a chave do dominio
     */
    public void registarTemperatura(String userId, int deviceId, byte[] temperaturaCifrada) {
        temperaturas.put(userId+":"+deviceId,temperaturaCifrada);
    }

    public void setDevices(Set<String> devices) {
        this.devices = devices;
    }

    public void setUtilizadores(Set<String> utilizadores) {
        this.utilizadores = utilizadores;
    }

    public void setTemperaturas(Map<String, byte[]> temperaturas) {
        this.temperaturas = temperaturas;
    }

    public void setChavesDominio(Map<String, byte[]> chavesDominio) {
        this.chavesDominio = chavesDominio;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("CREATOR=/VALUE/").append(criador).append(System.lineSeparator());
        sb.append("USERS=/VALUE/");
        for (String user : utilizadores) {
            sb.append(user).append(",");
        }
        sb.deleteCharAt(sb.length() - 1).append(System.lineSeparator());
        sb.append("DEVICES=/VALUE/");
        for (String device : devices) {
            sb.append(device).append(",");
        }
        sb.deleteCharAt(sb.length() - 1).append(System.lineSeparator());

        // imprimir temperaturas
        sb.append("TEMPERATURAS=/VALUE/");
        for (Map.Entry<String, byte[]> entry : temperaturas.entrySet()) {
            sb.append(entry.getKey()).append(",");
            sb.append(Base64.getEncoder().encodeToString(entry.getValue())).append(",");
        }
        sb.deleteCharAt(sb.length() - 1).append(System.lineSeparator());
        sb.append("CHAVESDOMINIO=/VALUE/");
        for (Map.Entry<String, byte[]> entry : chavesDominio.entrySet()) {
            sb.append(entry.getKey()).append(",");
            sb.append(Base64.getEncoder().encodeToString(entry.getValue())).append(",");
        }
        sb.deleteCharAt(sb.length() - 1).append(System.lineSeparator());
        return sb.toString();
    }
}
