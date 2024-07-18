package src;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;

public class IoTServer {
    private final static int DEFAULT_PORT = 12345;

    public static void main(String[] args) {
        try {
            verificarNumeroArgumentos(args);
            int port = getPort(args);

            ServerManager serverManager = new ServerManager(args);

            // Erro ao carregar keystore
            if (serverManager.getKeystore() == null) {
                System.exit(1);
            }

            //shutdown de todas as threads
            // Deteta CTRL+C no servidor e fecha todas as threads
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Terminar IoTServer");
                Thread.getAllStackTraces().keySet().forEach(Thread::interrupt);
            }));

            System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
            System.setProperty("javax.net.ssl.keyStore", serverManager.getKeystorePath());
            System.setProperty("javax.net.ssl.keyStorePassword", serverManager.getPasswordKeystore());
            ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();

            try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port)) {
                System.out.println("Server is listening on port " + port);
                while (true) {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    System.out.println("Server accepted new client");
                    Thread clientThread = new Thread(new ClientHandler(socket, serverManager));
                    clientThread.start();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifica se o numero de argumentos eh possivel
     *
     * @param args argumentos passados ao programa
     */
    private static void verificarNumeroArgumentos(String[] args) {
        if (args.length < 4 || args.length > 5) {
            System.err.println("Número de argumentos incorreto. Uso: IoTServer <port> <password-cifra> <keystore> <password-keystore> [<2FA-APIKey>]");
            System.exit(1);
        }
    }

    /**
     * Obtem o porto dado no programa e verifica se eh valido
     *
     * @param args do IoTServer
     * @return retorna DEFAULT_PORT se nao foi fornecido nenhum porto retorna -1 se
     * foi fornecido um porto mas nao tem formato ou nao eh valido retorna
     * porto dado nos argumentos
     */
    private static int getPort(String[] args) {
        if (args.length > 4) {
            try {
                int port = Integer.parseInt(args[0]);
                if (isValidPort(port)) {
                    return port;
                } else {
                    System.err.println("Porto inválido. Servidor terminado.");
                    System.exit(1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Invalido formato para porto. Servidor terminado.");
                System.exit(1);
            }
        }
        return DEFAULT_PORT;
    }

    /**
     * Verifica se o porto dado eh valido
     *
     * @param port o porto a verificar
     * @return true se valido senao falso
     */
    private static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

}