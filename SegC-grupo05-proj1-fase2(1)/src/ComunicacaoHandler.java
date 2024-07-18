package src;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ComunicacaoHandler {
    private final ObjectInputStream in;
    private final ObjectOutputStream out;

    public ComunicacaoHandler(ObjectInputStream in, ObjectOutputStream out) {
        this.in = in;
        this.out = out;
    }

    void flush() {
        try {
            out.flush();
        } catch (IOException e) {
        }
    }

    /**
     * Recebe a resposta
     *
     * @return a resposta
     */
    Object lerResposta() {
        Object response = null;
        try {
            response = in.readObject();
        } catch (IOException e) {
            System.err.println("Erro a ler resposta: " + e.getMessage());
        } catch (ClassNotFoundException e) {
            System.err.println("Erro a ler resposta: " + e.getMessage());
            System.exit(1);
        }
        return response;
    }

    /**
     * Envia uma mensagem
     *
     * @param mensagem Objeto contendo a mensagem a ser enviada.
     */
    void enviarMensagem(Object mensagem) {
        try {
            out.writeObject(mensagem);
            out.flush();
        } catch (IOException e) {
            System.err.println("Erro ao enviar mensagem: " + e.getMessage());
            System.exit(1);
        }
    }

    byte[] getHashNonceConcatenado(long nonce, String filePath) {
        try {
            byte[] fileContent = lerFicheiro(filePath);

            ByteArrayOutputStream concatenatedStream = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(concatenatedStream);
            dos.writeLong(nonce);
            dos.write(fileContent);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(concatenatedStream.toByteArray());
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Não conseguiu localizar ficheiro , erro ao construir hash");
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    private byte[] lerFicheiro(String filePath) throws IOException {
        FileInputStream fis = new FileInputStream(filePath);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            bos.write(buffer, 0, bytesRead);
        }
        fis.close();
        return bos.toByteArray();
    }
}
