import java.io.*;
import java.net.*;
import java.util.Scanner;

public class IoTDevice {
	// o porto default
	final static int DEFAULT_PORT = 12345;
	
	private String serverAddress;
	private int port;
	private int deviceId;
	private String userId;
	private StringBuilder comdsMenu;

	public IoTDevice(String serverAddress, int port, int deviceId, String userId) {
		this.serverAddress = serverAddress;
		this.port = port;
		this.deviceId = deviceId;
		this.userId = userId;
		this.comdsMenu = new StringBuilder();

		comdsMenu.append("Escolha um dos seguintes comandos:\n");
		comdsMenu.append("CREATE <dm> Criar dominio - utilizador é Owner\n");
		comdsMenu.append("ADD <user1> <dm> Adicionar utilizador <user1> ao domínio <dm>\n");
		comdsMenu.append("RD <dm> Registar o Dispositivo atual no domínio <dm>\n");
		comdsMenu.append("ET <float> Enviar valor <float> de Temperatura para o servidor.\n");
		comdsMenu.append("EI <filename.jpg> Enviar Imagem <filename.jpg> para o servidor.\n");
		comdsMenu.append(
				"RT <dm> Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões.\n");
		comdsMenu.append(
				"RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões.\n");
		comdsMenu.append("COMANDO:");
	}

	public static void main(String[] args) {
		if (args.length != 3 && args.length != 4) {
			System.err.println("Usage: IoTDevice <serverAddress>[:port] <dev-id> <user-id>");
			System.exit(1);
		}

		String[] serverAddressParts = args[0].split(":");
		String serverAddress = serverAddressParts[0];
		int port = DEFAULT_PORT;

		if (serverAddressParts.length == 2) {
			try {
				port = Integer.parseInt(serverAddressParts[1]);
			} catch (NumberFormatException e) {
				System.err.println("Invalid port number: " + serverAddressParts[1]);
				System.exit(1);
			}
		}

		int deviceId;
		try {
			deviceId = Integer.parseInt(args[1]);
		} catch (NumberFormatException e) {
			System.err.println("Device ID must be an integer");
			System.exit(1);
			return;
		}
		String userId = args[2];

		IoTDevice device = new IoTDevice(serverAddress, port, deviceId, userId);
		device.start();
	}

	public void start() {
		try (Socket clientSocket = new Socket(serverAddress, port);
				ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
				ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
						Scanner scanner = new Scanner(System.in)) {


			// USER E SENHA
			String response;
			out.writeObject(this.userId);

			do {
				System.out.print("Enter password: ");
				String password = scanner.nextLine();
				if(password.length() == 0) {
					response = "WRONG-PWD";
					System.out.println("Enter a valid password.");
				}
				else {
					out.writeObject(password);
					out.flush();
		            response = lerResposta(in);
		            if(response == null) return;
					System.out.println(response);
				}
			} while (response.equals("WRONG-PWD"));

			// DEVICE ID
			out.writeInt(this.deviceId);
			out.flush();
            response = lerResposta(in);
            if(response == null) return;
			System.out.println(response);

			while (response.equals("NOK-DEVID")) {
				System.out.print("Device ID encontra-se em uso. Insira outro deviceID (numero inteiro): ");
				this.deviceId = scanner.nextInt();
				scanner.nextLine(); 
				out.writeInt(this.deviceId);
				out.flush();
				response = (String) in.readObject();
				System.out.println(response);
			}

			// EXECUTAVEL ---- envia o nome do ficheiro e depois envia o tamanho do jar
			String nomeExecutavel = "IoTDevice.jar";
			File jarFile = new File(nomeExecutavel);
			out.writeObject(nomeExecutavel);
			out.flush();
			out.writeLong(jarFile.length());
			out.flush();
            response = lerResposta(in);
            if(response == null) return;
			System.out.println(response);
			if (response.equals("OK-TESTED")) {
				commandsHandler(scanner, in, out);
			}
		}
		catch (IOException | ClassNotFoundException e) {
			System.err.println("Erro ao comunicar com servidor.");
			System.out.println("Programa terminado.");
			return;
		}
	}
	
	/**
	 * Recebe comandos do cliente e envia pedidos ao servidor
	 * @param sc o scanner
	 * @param in 
	 * @param out
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private void commandsHandler(Scanner sc, ObjectInputStream in, ObjectOutputStream out)
			throws IOException, ClassNotFoundException {
		
		System.out.print(comdsMenu.toString());
		out.flush();
		String cmds;
		String[] splitedCmds;
		String response = null;

		while (true) {
			if (sc.hasNextLine()) {
				cmds = sc.nextLine();
				
				// separar por blankspaces
				splitedCmds = cmds.split("[\\s:]");

				
				// validação do comando mandado pelo utilizador. Se for válido,
				// mandá-lo para o servidor já repartido.
				switch (splitedCmds[0].toUpperCase()) {
				case "CREATE":
					if (splitedCmds.length == 2) {
						out.writeObject(splitedCmds);
	                    response = lerResposta(in);
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;

				case "ADD":
					if (splitedCmds.length == 3) {
						out.writeObject(splitedCmds);
	                    response = lerResposta(in);
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;

				case "RD":
					if (splitedCmds.length == 2) {
						out.writeObject(splitedCmds);
	                    response = lerResposta(in);
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;

				case "ET":
					if (splitedCmds.length == 2) {
						out.writeObject(splitedCmds);
	                    response = lerResposta(in);
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;

				case "EI":
					if (splitedCmds.length == 2) {
						String pathImagem = splitedCmds[1];
						try {
							File imagem = new File(pathImagem);
							
							if (!imagem.exists()) {
								System.err.println("Ficheiro não existe.");
								break;
							}
							// envia pedido de EI após encontrar imagem a enviar
							out.writeObject(splitedCmds);
							out.flush();
							
							try {
			                    enviarImagem(out, imagem);
			                    response = lerResposta(in);
			                    if(response == null) break;
			                } catch (IOException e) {
			                    System.err.println("Erro no envio da imagem: " + e.getMessage());
			                }
							
						} catch (IOException e) {
							System.err.println("Não foi possivel encontrar/ler imagem: " + e.getMessage());
						}
					}else {
						System.err.println("Formato inválido.");
					}
					break;
				case "RT":
					if (splitedCmds.length == 2) {
						out.writeObject(splitedCmds);
	                    response = lerResposta(in);
						if(response.equals("OK")) {
							receberFicheiro(in, ".txt");
						}
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;

				case "RI":
					if (splitedCmds.length == 3) {
						out.writeObject(splitedCmds);
						out.flush();
	                    response = lerResposta(in);
						if(response.equals("OK")) {
							receberFicheiro(in, ".jpg");
						}
					}
					else {
						System.err.println("Formato inválido.");
					}
					break;
				default:
					// caso o utilizador tenha mandado um comando inválido.
					System.err.println("Formato inválido.");
					break;
				}
				if(response != null) System.out.println("RESPOSTA SERVER: " + response);
				response = null;
				System.out.print("COMANDO:");
			}
		}
	}
	/**
	 * Envia imagem para o servidor
	 * @param out
	 * @param imagem a imagem a enviar
	 * @throws IOException
	 */
	private void enviarImagem(ObjectOutputStream out, File imagem) throws IOException {
		// envia tamanho da imagem
		out.writeObject(imagem.length()); 
		out.flush();
		
		// envia imagem
        byte[] buffer = new byte[1024];
        int bytesRead;
        try (FileInputStream fis = new FileInputStream(imagem);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(fis)) {
            while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            out.flush();
        }
		
	}

	/**
	 * Recebe ficheiro do server
	 * @param in 
	 * @param tipoFicheiro o tipo do ficheiro 
	 */
	private void receberFicheiro(ObjectInputStream in, String tipoFicheiro) {
		
		String nomeFicheiro;
		if(tipoFicheiro.equals(".jpg")) {
			nomeFicheiro = "RI-recebida" + tipoFicheiro;
		}
		else nomeFicheiro = "RT-recebido"+tipoFicheiro;
		
		File imageFile = new File(nomeFicheiro);

		try (FileOutputStream fout = new FileOutputStream(imageFile)) {

			long fileSize = (long) in.readObject();
			byte[] buffer = new byte[1024];
			int bytesRead;
			long totalBytesRead = 0;

			while (totalBytesRead < fileSize && (bytesRead = in.read(buffer)) != -1) {
				fout.write(buffer, 0, bytesRead);
				totalBytesRead += bytesRead;
			}

			fout.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	/**
	 * Recebe a resposta do servidor 
	 * @param in 
	 * @return a resposta do servidor
	 */
	private String lerResposta(ObjectInputStream in) {
	    String response = null;
	    try {
	        response = (String) in.readObject();
	        
	    } catch (IOException e) {
	        System.err.println("Erro a ler resposta do servidor / servidor não ativo");
	    } catch (ClassNotFoundException e) {
	        System.err.println("Erro a ler resposta do servidor" + e.getMessage());
	    }
	    return response;
	}

}
