import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class ClientHandler implements Runnable {

	// ficheiro hardcoded com informaçoes para validar programa do cliente
	private static final String APLICACAO_FILE_PATH = "aplicacao.txt";

	private Socket clientSocket;
	private IoTServer server;
	private ReentrantReadWriteLock serverLock;

	/**
	 * Constroi um novo clientHandler
	 * 
	 * @param clientSocket a socket do cliente
	 * @param server       o servidor
	 */
	public ClientHandler(Socket clientSocket, IoTServer server) {
		this.clientSocket = clientSocket;
		this.server = server;
		this.serverLock = server.getReadWriteLock();
	}

	@Override
	public void run() {

		String user = null;
		int dispositivoID = -1;

		try (Socket clientSocket = this.clientSocket;
				ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
				ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

			// 1-2 - Regista user nos dispositivos loggedIn
			user = (String) in.readObject();
			String password;
			String mensagem;

			do {
				password = (String) in.readObject();
				mensagem = autenticar(user, password, out);
				enviarMensagem(mensagem, out);
			} while (mensagem.equals("WRONG-PWD"));

			// 3-4 deviceID
			do {
				dispositivoID = in.readInt();
				mensagem = registarDispositivo(user, dispositivoID);
				enviarMensagem(mensagem, out);
			} while (mensagem.equals("NOK-DEVID"));

			// 5-6 validacao do programa do cliente
			boolean isClientValido = validarCliente(in);
			if (!isClientValido) {
				enviarMensagem("NOK-TESTED", out);
				System.err.println("Disconnecting client...");
				desconectarDispositivo(user, dispositivoID);
				server.ArmazenarDados();
				return;
			}
			enviarMensagem("OK-TESTED", out);

			// 7 - 10 Menu
			while (true) {

				String[] comando = (String[]) in.readObject();

				switch (comando[0].toUpperCase()) {

				case "CREATE":
					handleCreate(comando[1], user, out);
					break;
				case "ADD":
					handleAdd(user, comando[1], comando[2], out);
					break;
				case "RD":
					enviarMensagem(handleRd(user, dispositivoID, comando[1]), out);
					break;
				case "ET":
					handleEt(comando[1], user, dispositivoID, out);
					break;
				case "EI":
					handleEi(in, out, user, dispositivoID);
					break;
				case "RT":
					handleRt(comando[1], user, out);
					break;
				case "RI":
					String response = handleRi(comando[1], comando[2], user, out);
					String nomeImagem = comando[1] + "-" + comando[2] + ".jpg";
					File imagem = new File(server.getPastaImagens() + "//" + nomeImagem);
					enviarMensagem(response,out);
					if(response.equals("OK")) {
						enviarFicheiro(imagem, out);
					}
					break;
				default:
					break;
				}
			}

		} catch (IOException | ClassNotFoundException e) {
			System.err.println("Disconnecting client...");
			desconectarDispositivo(user, dispositivoID);
			server.ArmazenarDados();
			return;
		}
	}

	/**
	 * Verifica se o programa do cliente é valido
	 * 
	 * @param in
	 * @return true se programa é valido senao falso
	 */
	private boolean validarCliente(ObjectInputStream in) {
		try {
			BufferedReader br = new BufferedReader(new FileReader(APLICACAO_FILE_PATH));
			String line = br.readLine();
			String[] parts = line.split(":");
			String client_nome = parts[0];
			long client_size = Long.parseLong(parts[1]);
			br.close();

			String nomeExecutavel = (String) in.readObject();
			Long tamanhoExecutavel = in.readLong();

			return nomeExecutavel.equals(client_nome) && tamanhoExecutavel == client_size;
		} catch (IOException e) {
			return false;
		} catch (ClassNotFoundException e) {
			return false;
		}
	}

	/**
	 * Trata do pedido de CREATE <dm> Cria um novo dominio no servidor e envia
	 * mensagem "OK" para cliente Caso o dominio ja exista, envia mensagem "NOK"
	 * para cliente
	 * 
	 * @param dominio o dominio a ser criado
	 * @param userID  o id do user que vai criar o dominio
	 * @param out     stream para enviar mensagem ao cliente
	 */
	private void handleCreate(String dominio, String userID, ObjectOutputStream out) {

		serverLock.writeLock().lock();

		try {
			if (dominio == null || server.getDominios() == null)
				enviarMensagem("NOK", out);

			if (!server.getDominios().containsKey(dominio)) {
				server.getDominios().put(dominio, new String[] { userID, "NULL", "NULL" });
				// adicionar Criador a lista de utilizadores
				server.getDominios().get(dominio)[2] = userID;
				enviarMensagem("OK", out);
			} else {
				// devolve NOK se dominio a ser criado ja existe
				enviarMensagem("NOK", out);
			}
		} finally {
			serverLock.writeLock().unlock();
		}

	}

	/**
	 * Trata do pedido de ADD <user> <dominio> adiciona o utilizador <user1> ao
	 * domínio <dm> e envia mensagem "OK" para cliente Se utilizador nao é o criador
	 * do dominio entao envia NOPERM Se o dominio nao existe envia NODM Se o user
	 * nao existe envia NOUSER
	 * 
	 * @param user    o utilizador a ser adicionado
	 * @param dominio o dominio
	 * @param newUser
	 * @param out     stream para comunicar com cliente
	 */
	private void handleAdd(String user, String newUser, String dominio, ObjectOutputStream out) {

		serverLock.writeLock().lock();

		try {
			if (dominio == null || server.getDominios() == null || user == null || newUser == null
					|| server.getUtilizadores() == null)
				enviarMensagem("NODM", out);

			String[] properties = server.getDominios().get(dominio);

			// dominio nao existe
			if (properties == null)
				enviarMensagem("NODM", out);

			// utilizador nao é criador do dominio logo nao pode adicionar users
			else if (!properties[0].equals(user))
				enviarMensagem("NOPERM", out);

			// utilizador nao existe
			else if (!server.getUtilizadores().containsKey(newUser))
				enviarMensagem("NOUSER", out);

			// se user ainda nao pertencer ao dominio adiciona
			else if (!isUserInDomain(properties[2], newUser)) {
				properties[2] = properties[2] + " " + newUser;
				enviarMensagem("OK", out);

			} else {
				// Server devolve NOK se user ja pertencia ao dominio
				enviarMensagem("NOK", out);
			}
		} finally {
			serverLock.writeLock().unlock();
		}

	}

	/**
	 * Trata dos pedidos de RD <dm>, regista o dispositivo atual no dominio Se
	 * possivel envia mensagem "OK" Se utilizador atual nao pertencer ao dominio
	 * envia "NOPERM" Se o dominio nao existir envia "NODM"
	 * 
	 * @param user
	 * @param dispositivoID
	 * @param string
	 */
	private String handleRd(String user, int dispositivoID, String dominio) {

		serverLock.writeLock().lock();

		try {
			if (dominio == null || server.getDominios() == null || dispositivoID < 0 || user == null)
				return "NOK";

			// criador,devices (user:deviceid), utilizadores
			String[] properties = server.getDominios().get(dominio);

			// dominio nao existe
			if (properties == null)
				return "NODM";

			// utilizador atual nao se encontra registado no dominio
			if (!isUserInDomain(properties[2], user))
				return "NOPERM";

			// Se o deviceID ja se encontra no dominio entao devolve NOK
			if (isUserDeviceInDomain(dominio, user, Integer.toString(dispositivoID))) {
				return "NOK";
			}

			properties[1] = properties[1].equals("NULL") ? user + ":" + dispositivoID
					: properties[1] + " " + user + ":" + dispositivoID;

			return "OK";
		} finally {
			serverLock.writeLock().unlock();
		}

	}

	/**
	 * Obtem um ficheiro de texto com os dados de temperatura gravados no servidor
	 * de todos os dispositivos de um dado dominio
	 * 
	 * @param dominio
	 * @param out
	 * @return
	 */
	private void handleRt(String dominio, String user, ObjectOutputStream out) {

		serverLock.readLock().lock();

		try {
			// dominio nao existe
			if (!server.getDominios().containsKey(dominio)) {
				enviarMensagem("NODM", out);
			}

			// user nao pertence ao dominio
			else if (!verificarPermissoesLeitura(dominio, user)) {
				enviarMensagem("NOPERM", out);
			}

			else {
				// construir ficheiro
				File ficheiro = construirFicheiroTemperaturasDominio(dominio);
				if (ficheiro.length() == 0L) {
					enviarMensagem("NODATA", out);
				} else {
					enviarMensagem("OK", out);
					enviarFicheiro(ficheiro, out);
				}
				// apagar ficheiro que foi construido no servidor para enviar ao cliente
				apagarFicheiroDoServidor(ficheiro);
			}
		} finally {
			serverLock.readLock().unlock();

		}
	}

	/**
	 * Apaga o ficheiro que foi construido para enviar as temperaturas ao cliente
	 * 
	 * @param ficheiro o ficheiro das temperaturas construido no servidor
	 */
	private void apagarFicheiroDoServidor(File ficheiro) {
		try {
			if (ficheiro.exists()) {
				if (!ficheiro.delete()) {
					System.err.println("Erro ao apagar ficheiro do servidor: " + ficheiro.getName());
				}
			}
		} catch (SecurityException e) {
			System.err.println("Erro de segurança a apagar ficheiro do servidor: " + e.getMessage());
		}

	}

	/**
	 * Regista a temperatura de um dado user e dispositivo
	 * 
	 * @param temperatura a temperatura a registar
	 * @param user o id do user
	 * @param dispositivoID o device id
	 * @param out
	 */
	private void handleEt(String temperatura, String user, int dispositivoID, ObjectOutputStream out) {

		serverLock.writeLock().lock();

		try {
			float tempValue = Float.parseFloat(temperatura);

			// ver se user ja tem alguma temperatura registada mapa
			if (server.getTemperaturas().get(user + ":" + dispositivoID) == null) {
				server.getTemperaturas().put(user + ":" + dispositivoID, tempValue);
			} else {
				server.getTemperaturas().replace(user + ":" + dispositivoID, tempValue);
			}
			enviarMensagem("OK", out);
		} catch (NumberFormatException e) {
			enviarMensagem("NOK", out);
		} finally {
			serverLock.writeLock().unlock();

		}
	}

	/**
	 * Recebe a imagem do cliente e guarda na pasta imagens no servidor
	 * 
	 * @param in            stream para receber dados do cliente
	 * @param out           stream para enviar resposta ao cliente
	 * @param userId        o nome do cliente
	 * @param dispositivoID o id do dispositivo do cliente
	 */
	private void handleEi(ObjectInputStream in, ObjectOutputStream out, String userId, int dispositivoID) {
	    String nomeImagem = userId + "-" + dispositivoID + ".jpg";
	    System.out.println("IoTServer is copying image to file named " + nomeImagem);
	    File imageFile = new File(server.getPastaImagens(), nomeImagem);

	    try (FileOutputStream fout = new FileOutputStream(imageFile)) {
	    	
			long imageSize = (long) in.readObject();
			byte[] buffer = new byte[1024];
			int bytesRead;
			long totalBytesRead = 0;

			while (totalBytesRead < imageSize && (bytesRead = in.read(buffer)) != -1) {
				fout.write(buffer, 0, bytesRead);
				totalBytesRead += bytesRead;
			}

			fout.flush();
			
	        if(imageSize == 0) {
	        	enviarMensagem("NOK", out);
	        }
	        else {
	        	// Verificar se eh jpg
		        byte[] magicNumber = new byte[2];
		        try (RandomAccessFile raf = new RandomAccessFile(imageFile, "r")) {
		            raf.readFully(magicNumber);
		        }
		       // se nao for JPG
		        if (magicNumber[0] != (byte) 0xFF || magicNumber[1] != (byte) 0xD8) {
		            enviarMensagem("NOK", out);
		        }
		        else {
			        enviarMensagem("OK", out);
			        return;
		        }
	        }
			
	    } catch (IOException | ClassNotFoundException e) {
	    	e.printStackTrace();
	        enviarMensagem("NOK", out);
	    }

        apagarFicheiroDoServidor(imageFile);
	}


	/**
	 * Constroi o ficheiro com todos os dispositivos e respectivas temperaturas do
	 * dominio dado
	 * 
	 * @param dominio o dominio
	 * @return o ficheiro com as temperaturas dos dispositivos pertencentes ao
	 *         dominio
	 */
	private File construirFicheiroTemperaturasDominio(String dominio) {
		File temperatureDomain = new File(dominio + "-temperatures.txt");
		criarFicheiros(temperatureDomain);

		try (FileWriter fileWriter = new FileWriter(temperatureDomain, false)) {
			fileWriter.write("");

			for (Map.Entry<String, Float> entry : server.getTemperaturas().entrySet()) {
				if (server.getDominios().get(dominio)[1].contains(entry.getKey())) {
					fileWriter.write(entry.getKey() + "," + entry.getValue() + "\n");
				}

			}

		} catch (IOException e) {
			System.err.println("Error writing to file: " + e.getMessage());
		}

		return temperatureDomain;
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
	 * Verifica se tem permissoes de leitura para aceder a informacao de um dado
	 * dominio, ou seja se o user é o criador ou user desse dominio
	 * 
	 * @param dominio o dominio
	 * @param user    o user que pretende aceder
	 * @return
	 */
	private boolean verificarPermissoesLeitura(String dominio, String user) {
		// mapa dos dominios tem os users
		String[] properties = server.getDominios().get(dominio);

		if (properties[0].equals(user)) {
			return true;
		}

		// utilizador atual esta registado no dominio
		return properties != null && properties.length > 1 ? isUserInDomain(properties[2], user) : false;
	}

	/**
	 * Verifica se user tem permissao para aceder aos dados de um dispositivo
	 * 
	 * @param user                o id do user
	 * @param dispositivoDesejado o dispositivo
	 * @param wanted_deviceID
	 * @return TRUE se user tem permissoes, senao FALSE
	 */
	private boolean verificarPermissaoLeituraImagem(String user, String wanted_user, String wanted_deviceID) {
		// user apenas pode aceder a imagem de wanted_user:wanted_deviceID se pertencer
		// ao mesmo dominio
		// ou for dono

		Set<String> allDomains = server.getDominios().keySet();

		for (String domain : allDomains) {
			// <dominio , [criador,devices,users]
			if (isUserDeviceInDomain(domain, wanted_user, wanted_deviceID)
					&& verificarPermissoesLeitura(domain, user)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Verifica se utilizador tem autorizacao para adicionar device
	 * 
	 * @param allUsers
	 * @param userToTest
	 * @return
	 */
	private boolean isUserDeviceInDomain(String dominio, String user, String deviceID) {

		String[] properties = server.getDominios().get(dominio);

		if (properties == null || properties[1] == null || user == null)
			return false;

		// user1:1 user2:3
		String[] users = properties[1].split(" ");
		for (String currentUser : users) {
			String[] us = currentUser.split(":");
			if (user.equals(us[0]) && deviceID.equals(us[1]))
				return true;
		}
		return false;
	}

	/**
	 * Verifica se o utilizador pertence ao dominio
	 * 
	 * @param allUsers
	 * @param userToTest
	 * @return
	 */
	private boolean isUserInDomain(String allUsers, String userToTest) {
		if (allUsers == null || userToTest == null)
			return false;

		String[] users = allUsers.split(" ");
		for (String currentUser : users) {
			if (currentUser.equals(userToTest))
				return true;
		}
		return false;
	}

	/**
	 * Quando cliente se descontecta eh preciso retirar o dispositivo dos
	 * dispositivos ativos
	 * 
	 * @param user          o userID do dispositivo
	 * @param dispositivoID o id do dispositivo
	 */
	private void desconectarDispositivo(String user, int dispositivoID) {

		serverLock.writeLock().lock();
		try {
			server.getDevicesLoggedIn().get(user).remove(dispositivoID);

			if (server.getDevicesLoggedIn().get(user).size() == 0) {
				server.getDevicesLoggedIn().remove(user);
			}
		} catch (NullPointerException e) {
			return;
		} catch (Exception e) {
			return;
		} finally {
			serverLock.writeLock().unlock();
		}
	}

	/**
	 * Trata do pedido RI primeiro verifica se o user tem permissoes para aceder a
	 * imagem, Se sim envia a imagem ao cliente
	 *
	 * @param dispositivoDesejado o nome do IoTDevice a quem pertence a imagem
	 * @param user                o cliente que tenta aceder a imagem
	 * @param user2
	 * @param out                 stream para enviar mensagens a cliente
	 */
	private String handleRi(String wanted_user, String wanted_deviceID, String user, ObjectOutputStream out) {

		serverLock.readLock().lock();
		String response = "NOK";

		try {
			Integer wanted_device = Integer.parseInt(wanted_deviceID);
			// se nao existir esse user ou existir esse user mas nao existir o deviceID
			if (!server.getUtilizadores().containsKey(wanted_user) || deviceIdExists(wanted_user, wanted_device) == 0)
				response = "NOID";

			else if (!verificarPermissaoLeituraImagem(user, wanted_user, wanted_deviceID))
				response = "NOPERM";

			else {
				String nomeImagem = wanted_user + "-" + wanted_deviceID + ".jpg";
				File imagem = new File(server.getPastaImagens() + "//" + nomeImagem);

				if (!imagem.exists() || imagem.length() == 0L) {
					response = "NODATA";
				} else {
					// envia OK para indicar que vai enviar ficheiro
					response = "OK";
				}

			}
			return response;
		} catch (NumberFormatException e) {
			return "NOK";

		} finally {
			serverLock.readLock().unlock();
		}
	}

	/**
	 * Verifica se o userID:dispositivoID existe no servidor
	 * 
	 * @param wanted_user     o userID a verificar
	 * @param wanted_deviceID o dispositivoID a verificar
	 * @return 1 se existir 0 se nao existir -1 se erro
	 */
	private int deviceIdExists (String wanted_user, Integer wanted_deviceID) {
	    try {
	        if (wanted_user == null)
	            return -1;

	        Set<Integer> devids = server.getDispositivos().get(wanted_user);

	        if (devids == null)
	            return 0;

	        return devids.contains(wanted_deviceID) ? 1 : 0;
	    } catch (Exception e) {
	        return -1;
	    }
	}

	/**
	 * Envia uma imagem para o cliente
	 * 
	 * @param imagem a imagem que queremos enviar
	 * @param out    stream para enviar ao cliente
	 */
	private void enviarFicheiro(File ficheiro, ObjectOutputStream out) {

		byte[] buffer = new byte[1024];
		int bytesRead;
		try (FileInputStream fis = new FileInputStream(ficheiro);
				BufferedInputStream bufferedInputStream = new BufferedInputStream(fis)) {

			out.writeObject(ficheiro.length());
			out.flush();

			while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
				out.flush();
			}
		} catch (IOException e) {
			System.err.println("Erro ao enviar ficheiro/imagem ao servidor.");
		}

	}

	/**
	 * Regista dispositivo no ficheiro que contem todos os users que estao
	 * conectados ao servidor num dado momento e também no registo geral de
	 * dispositivos desses users
	 * 
	 * @param user          o user do dispositivo
	 * @param dispositivoID o numero do dispositivo
	 * @return
	 */
	private String registarDispositivo(String user, int dispositivoID) {
		if (dispositivoID < 0 || user == null)
			return "NOK-DEVID";

		serverLock.writeLock().lock();

		try {
			// se foi possivel adicionar um novo dispositivo online
			if (adicionarDispositivoConectado(user, dispositivoID)) {
				// entao atualizamos o geral porque esse dispositivo pode ainda nunca se ter
				// ligado ao servidor
				adicionarDispositivo(user, dispositivoID);
				return "OK-DEVID";
			}
			return "NOK-DEVID";
		} finally {
			serverLock.writeLock().unlock();
		}

	}

	private void adicionarDispositivo(String user, int dispositivoID) {

		Set<Integer> dev_ids = server.getDispositivos().get(user);

		if (dev_ids == null) {
			dev_ids = new HashSet<Integer>();
		}
		if (dev_ids.add(dispositivoID)) {
			server.getDispositivos().put(user, dev_ids);
		}

	}

	/**
	 * Adiciona um novo dispositivo que está conectado ao servidor
	 * 
	 * @param user
	 * @param dispositivoID
	 */
	private boolean adicionarDispositivoConectado(String user, int dispositivoID) {

		Set<Integer> dev_ids = server.getDevicesLoggedIn().get(user);
		// se user ainda nao tem nenhum deviceID associado
		if (dev_ids == null) {
			dev_ids = new HashSet<Integer>();
		}

		if (dev_ids.add(dispositivoID)) {
			server.getDevicesLoggedIn().put(user, dev_ids);
			return true;

		}
		return false;

	}

	/**
	 * Autentica user
	 * 
	 * @param userID   o id do utilizador
	 * @param password a password
	 * @param in
	 * @return a mensagem a enviar a cliente
	 */
	private String autenticar(String userID, String password, ObjectOutputStream out) {
		if (userID == null || password == null)
			return "NOK";

		serverLock.writeLock().lock();

		try {
			// Verificar se userID existe e password correta
			if (server.getUtilizadores().containsKey(userID)) {
				String passwordGuardada = server.getUtilizadores().get(userID);
				return passwordGuardada.equals(password) ? "OK-USER" : "WRONG-PWD";
			}

			server.getUtilizadores().put(userID, password);
			server.getDevicesLoggedIn().put(userID, new HashSet<Integer>());

			return "OK_NEW_USER";
		} finally {
			serverLock.writeLock().unlock();

		}
	}

	/**
	 * Envia uma mensagem ao cliente
	 * 
	 * @param mensagem a mensagem a enviar
	 * @param out      a socket do cliente que vai receber a mensagem
	 */
	private void enviarMensagem(Object mensagem, ObjectOutputStream out) {
		try {
			out.writeObject(mensagem);
			out.flush();
		} catch (IOException e) {
			System.err.println("Error sending message to client.");
			e.printStackTrace();
		}

	}

}