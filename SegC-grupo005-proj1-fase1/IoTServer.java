import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class IoTServer {

	final static int DEFAULT_PORT = 12345;
	
	private final ReentrantReadWriteLock readWriteLock;

	// Ficheiros servidor
	private File ficheiroUtilizadores;
	private File ficheiroDominios;
	private File ficheiroTemperaturas;
	private File ficheiroDispositivos;
	

	private File pastaImagens;
	private Map<String, Float> temperaturas; // <user:deviceID, temp>
	private Map<String, String[]> dominios; // <dominio , [criador,devices,users]
	private Map<String, String> utilizadores; // mapa de <userID, password>
	private Map<String, Set<Integer>> dispositivosLoggedIn; // <users,lista de dispositivos>
	private Map<String, Set<Integer>> dispositivos; // <users,lista de dispositivos>

	/**
	 * Constroi novo server e cria ficheiros se nao existirem ainda
	 */
	public IoTServer() {
		this.dispositivosLoggedIn = new HashMap<>();
		this.dispositivos = new HashMap<>();
		this.utilizadores = new HashMap<>();
		this.temperaturas = new HashMap<>();
		this.dominios = new HashMap<>();
		this.ficheiroUtilizadores = new File("users.txt");
		this.ficheiroTemperaturas = new File("temperatura.txt");
		this.ficheiroDispositivos = new File("dispositivos.txt");
		this.ficheiroDominios = new File("dominios.txt");
		this.readWriteLock = new ReentrantReadWriteLock(true);

		server_init();
	}

	/**
	 * Inicializa todas as estruturas e ficheiros necessários para o servidor
	 */
	private void server_init() {

		criarFicheiros(ficheiroUtilizadores);
		loadUtilizadores();
		criarFicheiros(ficheiroDispositivos);
		loadDispositivos();
		criarFicheiros(ficheiroDominios);
		loadDominios();
		criarFicheiros(ficheiroTemperaturas);
		loadTemperaturas();
		// Cria pasta para guardar imagens recebidas pelos clientes
		this.pastaImagens = new File(System.getProperty("user.dir"), "imagens/");

		// se a pasta imagens nao existir => cria
		if (!this.pastaImagens.exists()) {
			this.pastaImagens.mkdir();
		}

	}

	/**
	 * Faz load para o mapa da informacao dos dados das temperaturas dos
	 * dispositivos
	 */
	private void loadTemperaturas() {

		/**
		 * EXEMPLO FICHEIRO TEMPERATURA
		 * 
		 * userID:DeviceID,temp\n
		 */

		try {
			Scanner sc = new Scanner(this.ficheiroTemperaturas);
			sc.useDelimiter(System.lineSeparator());

			while (sc.hasNext()) {
				String line = sc.nextLine();
				String[] data = line.split(",");
				if (data.length == 2) {
					this.temperaturas.put(data[0], Float.valueOf(data[1]));
				}

			}
			sc.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Faz load para o mapa da informacao dos dados dos dominios que estao no
	 * servidor
	 */
	private void loadDominios() {

		/**
		 * EXEMPLO FICHEIRO DOMINIOS
		 * 
		 * Dominio,Criador,user1:device2 user2:device3,user1 user2\n
		 */

		if (this.ficheiroDominios == null || dominios == null) {
			throw new IllegalArgumentException("Domain or Map cannot be null");
		}

		try (Scanner scanner = new Scanner(this.ficheiroDominios)) {
			scanner.useDelimiter("\n");

			while (scanner.hasNext()) {
				String domProperties = scanner.next();
				String[] allProperties = domProperties.split(",", 2);
				String[] createrDeviceUser = allProperties[1].split(",");
				dominios.put(allProperties[0], createrDeviceUser);
			}
		} catch (FileNotFoundException e) {
			System.err.println("File not found: " + this.ficheiroDominios.getAbsolutePath());
			e.printStackTrace();
		}
	}
	
	/**
	 * Permite obter a read write lock
	 * do server
	 * @return a readwrite lock
	 */
	public ReentrantReadWriteLock getReadWriteLock() {
		return this.readWriteLock;
	}
	

	/**
	 * Faz load para o mapa de users com os utilizadores que se registaram no
	 * servidor
	 */
	private void loadUtilizadores() {
		/**
		 * EXEMPLO FICHEIRO UTILIZADORES
		 * 
		 * userID:DeviceID,temp\n
		 */
		try {
			Scanner sc = new Scanner(this.ficheiroUtilizadores);
			sc.useDelimiter(System.lineSeparator());

			while (sc.hasNext()) {
				String line = sc.nextLine();
				String[] data = line.split(":");
				if (data.length == 2) {
					this.utilizadores.put(data[0], data[1]);
				}

			}
			sc.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Acede ao ficheiro dispositivos e carrega a informacao para mapa com todos os
	 * dispositivos do servidor
	 */
	private void loadDispositivos() {
		try {
			Scanner sc = new Scanner(this.ficheiroDispositivos);
			sc.useDelimiter(System.lineSeparator());

			while (sc.hasNext()) {
				String line = sc.nextLine();
				String[] data = line.split(":");
				String userID = data[0];
				Set<Integer> dev_ids = new HashSet<>();

				for (int i = 1; i < data.length; i++) {
					try {
						int id = Integer.parseInt(data[i]);
						dev_ids.add(id);

					} catch (NumberFormatException e) {
						continue;
					}
				}
				this.dispositivos.put(userID, dev_ids);
			}
			sc.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Cria ficheiro file se não existir ainda
	 * 
	 * @param file o ficheiro a criar
	 */
	private void criarFicheiros(File file) {
		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * @return the ficheiroUtilizadores
	 */
	public File getFicheiroUtilizadores() {
		return ficheiroUtilizadores;
	}

	/**
	 * @return the ficheiroDispositivos
	 */
	public File getFicheiroDispositivos() {
		return ficheiroDispositivos;
	}
	
	/**
	 * @return the ficheiroDominios
	 */
	public File getFicheiroDominios() {
		return ficheiroDominios;
	}

	/**
	 * @return the ficheiroTemperaturas
	 */
	public File getFicheiroTemperaturas() {
		return ficheiroTemperaturas;
	}

	/**
	 * @return the pastaImagens
	 */
	public File getPastaImagens() {
		return pastaImagens;
	}

	/**
	 * @return the temperaturas
	 */
	public Map<String, Float> getTemperaturas() {
		return temperaturas;
	}

	/**
	 * @return the dominios
	 */
	public Map<String, String[]> getDominios() {
		return dominios;
	}

	/**
	 * @return the utilizadores
	 */
	public Map<String, String> getUtilizadores() {
		return utilizadores;
	}

	/**
	 * @return the devices loggedIn 
	 */
	public Map<String, Set<Integer>> getDevicesLoggedIn() {
		return dispositivosLoggedIn;
	}
	
	/**
	 * @return the devices loggedIn 
	 */
	public Map<String, Set<Integer>> getDispositivos() {
		return dispositivos;
	}
	
	public static void main(String[] args) {

		int port = getPort(args);

		if (port == -1) {
			System.out.println("Try again with a valid port");
			return;
		}
		

		try (ServerSocket serverSocket = new ServerSocket(port)) {
			System.out.println("Server is listening on port " + port);
			IoTServer server = new IoTServer();
			
			//shutdown de todas as threads
			
			// Deteta CTRL+C no servidor e fecha todas as threads
	        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
	            server.ArmazenarDados();
	            System.out.println("Terminar IoTServer");
	            Thread.getAllStackTraces().keySet().forEach(Thread::interrupt);
	        }));
	        
			
			while (true) {
				Socket clientSocket = serverSocket.accept();
				Thread clientThread = new Thread(new ClientHandler(clientSocket, server));
				clientThread.start();
			}
		} catch (IOException e) {
			System.err.println("Error starting the server: " + e.getMessage());
		}
	}
	
	/**
	 * Guarda tudo o que esta localmente armazenados 
	 * nos ficheiros para que a informacao seja persistente
	 */
	void ArmazenarDados() {
		System.out.println("Armazenar dados...");
		updateDispositivosFile();
		updateTemperaturaFile();
		updateUsersFile();
		updateDominiosFile();
	}
	
	/**
	 * Armazena a informacao local dos dominios
	 * para o ficheiro com todos os dominios 
	 */
	
	private void updateDominiosFile() {
		readWriteLock.readLock().lock();
		
		try {
		
			if (ficheiroDominios == null || dominios == null) {
				return;
			}
			
			synchronized(ficheiroDominios) {
	
				try (FileWriter fileWriter = new FileWriter(ficheiroDominios, false)) {
					fileWriter.write(""); 
					for (Map.Entry<String, String[]> entry : dominios.entrySet()) {
						fileWriter.write(entry.getKey() + "," + entry.getValue()[0] + "," + entry.getValue()[1] + ","
								+ entry.getValue()[2] + "\n");
					}
				} catch (IOException e) {
					return;
				}
			}
		}finally {
			readWriteLock.readLock().unlock();
		}
		
	}

	/**
	 * Armazena a informacao local dos users
	 * para o ficheiro com todos os utilizadores 
	 */
	
	private void updateUsersFile() {
		readWriteLock.readLock().lock();
		
		try {
			synchronized(ficheiroUtilizadores) {
				cleanFile(ficheiroUtilizadores);
				try (FileWriter add = new FileWriter(ficheiroUtilizadores, true)) { // Append mode
					utilizadores.forEach((key, value) -> {
						try {
							add.write(key + ":" + value + "\n");
						} catch (IOException e) {
							e.printStackTrace();
						}
					});
					add.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}finally {
			readWriteLock.readLock().unlock();
		}
		
	}

	/**
	 * Armazena a informacao local das temperaturas
	 * para o ficheiro com todos as temperaturas dos
	 * dispositivos
	 */
	private void updateTemperaturaFile() {
		/**
		 * Estamos a ler o mapa das temperaturas
		 * logo podem estar vários a ler,
		 * contudo estamos a escrever no ficheiro das temperaturas
		 * e só pode ser uma thread a escrever no ficheiro das temperaturas então usamos synchronized
		 */
		readWriteLock.readLock().lock();
		
		try {
			
			synchronized(ficheiroTemperaturas) {
				if (ficheiroTemperaturas == null || temperaturas == null) {
					return;
				}
		
				try (FileWriter fileWriter = new FileWriter(ficheiroTemperaturas, false)) {
					fileWriter.write("");
		
					for (Map.Entry<String, Float> entry : temperaturas.entrySet()) {
						fileWriter.write(entry.getKey() + "," + entry.getValue() + "\n");
					}
				} catch (IOException e) {
					return;
				}
			}
		}finally {
			readWriteLock.readLock().unlock();
			
		}
		
	}

	/**
	 * Armazena no ficheiro dos dispositivos a
	 * informaçao guardada localmente no mapa dos
	 * dispositivos
	 */
	private void updateDispositivosFile() {
		readWriteLock.readLock().lock();
		try {
			synchronized(ficheiroDispositivos) {

			cleanFile(ficheiroDispositivos);
	
			try (FileWriter add = new FileWriter(ficheiroDispositivos, true)) {
	
				dispositivos.forEach((key, value) -> {
					try {
						add.write(key);
	
						for (Integer dev_id : value) {
							add.write(":");
							add.write(dev_id.toString());
						}
						add.write(System.lineSeparator());
					} catch (IOException e) {
						System.err.println("Error updating dispositivos file");
					}
				});
				add.close();
			}catch (IOException e) {
				System.err.println("Error finding dispositivos file");
			}
		  }
		}finally {
			readWriteLock.readLock().unlock();
		}
	}
	/**
	 * Remove todo o conteudo de um dado ficheiro
	 * 
	 * @param ficheiro o ficheiro a limpar
	 */
	public void cleanFile(File ficheiro) {
		try {
			FileWriter fileWriter = new FileWriter(ficheiro, false);
			fileWriter.write(""); // para limpar conteudo atual do ficheiro
			fileWriter.close();
		} catch (IOException e1) {
			e1.printStackTrace();
		}

	}
	/**
	 * Obtem o porto dado no programa e verifica se eh valido
	 *
	 * @param argumentos do IoTServer
	 * @return retorna DEFAULT_PORT se nao foi fornecido nenhum porto retorna -1 se
	 *         foi fornecido um porto mas nao tem formato ou nao eh valido retorna
	 *         porto dado nos argumentos
	 */
	private static int getPort(String[] args) {
		if (args.length > 0) {
			try {
				int port = Integer.parseInt(args[0]);
				if (isValidPort(port)) {
					return port;
				} else {
					System.err.println("Invalid port. Using the default port " + DEFAULT_PORT);
					return -1;
				}
			} catch (NumberFormatException e) {
				System.err.println("Invalid port format. Using the default port " + DEFAULT_PORT);
				return -1;
			}
		} else {
			return DEFAULT_PORT;
		}
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
