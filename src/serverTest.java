import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class ServerThread implements Runnable {
	private final ServerSocket serverSocket;
	private final ExecutorService pool;
	static ArrayList<String> activeUsers = new ArrayList<String>();
	static ArrayList<PublicKey> publicKeysList = new ArrayList<PublicKey>();
	//assigning pool of threads

	public ServerThread(int port, int poolSize)
			throws IOException {
		serverSocket = new ServerSocket(port);
		pool = Executors.newFixedThreadPool(poolSize);
	}

	public void run() { // run the service
		try {
			for (;;) {
				pool.execute(new Handler(serverSocket.accept()));
			}
		} catch (IOException ex) {
			pool.shutdown();
		}
	}
}

class Handler extends JFrame implements Runnable {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;
	private JTextField userText;
	private JTextArea chatWindow;
	private DataOutputStream output;
	private DataInputStream input;
	private ServerSocket server;
	private Socket connection;
	String username;
	String password;
	private String user;
	private String connectToUser ="";
	DataInputStream dis1;
	DataInputStream dis2;
	DataInputStream dis3;
	DataInputStream dis4;
	static java.sql.Connection conn = null;
	static Statement stmt;
	ResultSet rs;
	KeyPair serverKey;
	PublicKey clientPublicKey;
	static ArrayList<String> userDetails  = null;

	Handler(Socket connection) { this.connection = connection; } 
	public void run() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(0,0,500,500);
		try {
			setUI();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void setUI() throws Exception{
		setTitle("Messenger");
		userText= new JTextField();
		userText.setFont(new Font("courier", Font.PLAIN, 25));
		userText.setEditable(false);
		userText.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						try {
							encryption(userText.getText());
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						userText.setText("");
					}
				}
		);
		add(userText, BorderLayout.NORTH);
		chatWindow = new JTextArea();
		chatWindow.setFont(new Font("courier", Font.PLAIN, 20));
		add (new JScrollPane(chatWindow));
		setSize(300,150);
		setVisible(false);
		infoExchange();
	}

	private void infoExchange()throws Exception{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		serverKey = keyGen.generateKeyPair();

		ObjectOutputStream output = new ObjectOutputStream(connection.getOutputStream());
		output.writeObject(serverKey.getPublic());
		output.flush();

		String timeString = Long.toString(new Date().getTime());
		dis1 = new DataInputStream(connection.getInputStream());
		int length = dis1.readInt();

		byte[] cipherText = null;
		if(length>0) {
			cipherText = new byte[length];
			dis1.readFully(cipherText, 0, cipherText.length);
		}
		System.out.println(length);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		System.out.println(cipherText);
		String usernameTime = new String(cipher.doFinal(cipherText));
		int index = usernameTime.indexOf("[");
		username =usernameTime.substring(0,index);
		String Timestamp =usernameTime.substring(index+1,usernameTime.length());
		long sub1 = Long.parseLong(Timestamp.substring(0,(Timestamp.length())/2));
		long sub2 = Long.parseLong(Timestamp.substring((Timestamp.length())/2));
		long s1 = Long.parseLong(timeString.substring(0,(timeString.length())/2));
		long s2 = Long.parseLong(timeString.substring((timeString.length())/2));

		if (s1-sub1 ==0){
			if (s2-sub2 > 1000){
				System.out.println("Replayed message");
				closeConn();
			}
			else{
				System.out.println(s2-sub2);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
			closeConn();
		}

		dis2 = new DataInputStream(connection.getInputStream());
		int length1 = dis2.readInt();

		byte[] cipherText1 = null;
		if(length1>0) {
			cipherText1 = new byte[length1];
			dis2.readFully(cipherText1, 0, cipherText1.length);
		}
		Cipher cipher1 = Cipher.getInstance("RSA");
		cipher1.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		byte[] pass = cipher1.doFinal(cipherText1);
		//System.out.println(pass);
		StringBuilder sb = new StringBuilder();
		for (byte b : pass) {
			sb.append(String.format("%02X ", b));
		}
		//System.out.println(sb.toString());

		String passwordTime= sb.toString();
		System.out.println(passwordTime);
		password =passwordTime.substring(0,97)+" ";
		System.out.println(password);
		String Timestamp1 =passwordTime.substring(97,passwordTime.length()).replaceAll("\\s+","");
		System.out.println(Timestamp1);
		long sub11 = Long.parseLong(Timestamp1.substring(0,(Timestamp1.length())/2));
		long sub21 = Long.parseLong(Timestamp1.substring((Timestamp1.length())/2));

		if (s1-sub11 ==0){
			if (s2-sub21 > 60){
				System.out.println("Replayed message");
				closeConn();
			}
			else{
				System.out.println(s2-sub21);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
			closeConn();
		}

		dis3 = new DataInputStream(connection.getInputStream());
		int length2 = dis3.readInt();

		byte[] cipherText2 = null;
		if(length2>0) {
			cipherText2 = new byte[length2];
			dis3.readFully(cipherText2, 0, cipherText2.length);
		}

		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String emailTime = new String(cipher2.doFinal(cipherText2));
		int index11 = emailTime.indexOf("[");
		String email =emailTime.substring(0,index11);
		String Timestamp11 =emailTime.substring(index11+1,emailTime.length());
		long sub111 = Long.parseLong(Timestamp11.substring(0,(Timestamp11.length())/2));
		long sub211 = Long.parseLong(Timestamp11.substring((Timestamp11.length())/2));

		if (s1-sub111 ==0){
			if (s2-sub211 > 60){
				System.out.println("Replayed message");
				closeConn();
			}
			else{
				System.out.println(s2-sub211);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
			closeConn();
		}

		dis4 = new DataInputStream(connection.getInputStream());
		int length3 = dis4.readInt();

		byte[] cipherText3 = null;
		if(length3>0) {
			cipherText3 = new byte[length3];
			dis4.readFully(cipherText3, 0, cipherText3.length);
		}

		Cipher cipher3 = Cipher.getInstance("RSA");
		cipher3.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String infoTime = new String(cipher3.doFinal(cipherText3));
		int index111 = infoTime.indexOf("[");
		String info =infoTime.substring(0,index111);
		String Timestamp111 =infoTime.substring(index111+1,infoTime.length());
		long sub12 = Long.parseLong(Timestamp111.substring(0,(Timestamp111.length())/2));
		long sub22 = Long.parseLong(Timestamp111.substring((Timestamp111.length())/2));

		if (s1-sub12 ==0){
			if (s2-sub22 > 60){
				System.out.println("Replayed message");
				closeConn();
			}
			else{
				System.out.println(s2-sub22);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
			closeConn();
		}

		ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
		clientPublicKey = (PublicKey) ois.readObject();

//		System.out.println(username);
//    	System.out.println(password);
//    	System.out.println(email);
//    	System.out.println(info);
//		System.out.println(clientPublicKey);
		InetAddress inet = connection.getInetAddress();
		int portNum = connection.getPort();
		System.out.println(inet+":"+ portNum);
		databaseCheck(username,password,clientPublicKey,info,inet,portNum,email);
	}

	private void databaseCheck(String username, String password, PublicKey clientPublicKey, String info, InetAddress inet, int portNum, String email) throws Exception{
		String msg = "";
		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
		String url = ("jdbc:sqlite:/Users/PranathiVasireddy/Desktop/sqlite/test.db");
		conn = DriverManager.getConnection(url);
		stmt = conn.createStatement();
		String sql = ("SELECT USERNAME FROM LOGIN WHERE USERNAME =?");
		PreparedStatement pstmt = conn.prepareStatement( sql );
		pstmt.setString(1,username);
		ResultSet rs = pstmt.executeQuery();
		if (rs.next())
		{
			System.out.println("Passed username");
			String seq = ("SELECT PASSWORD FROM LOGIN WHERE PASSWORD= ? AND USERNAME= ?");
			PreparedStatement pstmt1 = conn.prepareStatement( seq );
			pstmt1.setString(1, password);
			pstmt1.setString(2, username);
			ResultSet res = pstmt1.executeQuery();
			if (res.next() && info.equals("Sign In")) {//username exists, password exists, Sign in
				System.out.println("Passed password");
				msg = "OK";
				dos.writeUTF(msg);
				String sq = ("UPDATE LOGIN SET ADDRESS = '"+inet+"', PORT = '"+portNum+"', PUBLIC_KEY='"+clientPublicKey+"' WHERE USERNAME = '"+username+"'");
				stmt.execute(sq);
				addToActiveUsersList(username);
				sql = ("SELECT PORT,PUBLIC_KEY, ADDRESS FROM LOGIN WHERE USERNAME ='"+username+"'");
				ResultSet rs1 = stmt.executeQuery(sql);
				userDetails = findUserDetails(rs1);
				connectionCheck();
			}
			else{
				if (info.equals("Sign Up")){//username exists, password doesn't exists, Sign up
					//username exists, password exists, Sign up
					msg = "Exists";
					closeDBConn();
				}
				else{// username exists, password doesn't exists, Sign in
					msg = "Not Cool";
					closeDBConn();
				}
				dos.writeUTF(msg);
			}
		}
		else{//username doesn't exists
			String seq = ("SELECT EMAIL_ID FROM LOGIN WHERE EMAIL_ID= ?");
			PreparedStatement pstmt1 = conn.prepareStatement( seq );
			pstmt1.setString(1, email);
			ResultSet res = pstmt1.executeQuery();//returns false even if data exists
			if (!res.next()){//email doesn't exists
				if (info.equals("Sign Up") ){//Sign up and email is new
					String seql = ("INSERT INTO LOGIN (USERNAME,PASSWORD,PUBLIC_KEY,ADDRESS,PORT,EMAIL_ID) " +
							"VALUES(?,?,?,?,?,?)");
					String add = inet.toString();
					String ckey = clientPublicKey.toString();
					PreparedStatement pstmt2 = conn.prepareStatement( seql );
					pstmt2.setString(1, username);
					pstmt2.setString(2, password);
					pstmt2.setString(3, ckey);
					pstmt2.setString(4, add);
					pstmt2.setLong(5, portNum);
					pstmt2.setString(6, email);
					pstmt2.execute();
					msg = "Inserted";
				}
				else{
					msg = "Not Cool";
					closeDBConn();
				}
			}

			else{//email exists
				msg = "Exists";
			}
			dos.writeUTF(msg);
			closeDBConn();
		}
	}

	private void connectionCheck() throws Exception {
		DataInputStream dis = new DataInputStream(connection.getInputStream());
		int length = dis.readInt();

		byte[] cipherText = null;
		if(length>0) {
			cipherText = new byte[length];
			dis.readFully(cipherText, 0, cipherText.length);
		}

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String username = new String(cipher.doFinal(cipherText));
		String sql = ("SELECT USERNAME FROM LOGIN WHERE USERNAME = ?");
		PreparedStatement pstmt = conn.prepareStatement( sql );
		pstmt.setString(1,username);
		ResultSet rs = pstmt.executeQuery();
		connectToUser = username;
		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
		if(!rs.next()){//no such user
			String msg = "Impossible";
			dos.writeUTF(msg);
			// connectionCheck();
		}
		else{//registered user
			setupStreams();
			whileChatting();
			closeConn();
			closeDBConn();
		}
	}
	private void setupStreams()throws Exception{
		output = new DataOutputStream(connection.getOutputStream());
		output.flush();
		input = new DataInputStream(connection.getInputStream());
	}

	private void closeConn() throws SQLException{
		try{
			//conn.close();
			dis1.close();
			dis2.close();
			output.close();
			input.close();
			connection.close();
		}catch(IOException io){
			io.printStackTrace();
		}
	}

	private void sendMessage(String message){
		try{
			output.writeUTF(message);
			output.flush();
		}catch(IOException io){
			chatWindow.append("\n ERROR: cant't send this message");
		}
	}

  private void whileChatting()throws Exception{
		// during the chat conversation
		try{
			Date date = new Date();
			String token = generateToken();
			output.flush();
			String message = "";
			ArrayList<String> clientDetails = null;
			if(ServerThread.activeUsers.contains(connectToUser)){
				String sql = ("SELECT PORT,PUBLIC_KEY, ADDRESS FROM LOGIN WHERE USERNAME ='"+connectToUser+"'");
				ResultSet rs = stmt.executeQuery(sql);
				clientDetails = findUserDetails(rs); // find details of client to which the first client wants to connect to.
				while (clientDetails.size()!= 3){
					clientDetails.add("");
				}
				message = connectToUser +";"+ token+";"+clientDetails.get(0)+";"+clientDetails.get(1)+";"+clientDetails.get(2)+";" +getDateTime();
				System.out.println("message is :"+message);
			}
			sendMessage(message);
			String setupDoneFlag = "0";
			setupDoneFlag = input.readUTF();
			System.out.println("done flag:" + setupDoneFlag);
			if(setupDoneFlag.equals("1")){

				output.writeUTF("1");
				output.flush();
				//System.out.println("closing streams");
				//break;
			}
			//}
			if (setupDoneFlag.equals("0")){ /// take care
				output.writeUTF("0");
				output.flush();

				output.writeUTF("connected");
				output.flush();

			}
			else{
				if(ServerThread.activeUsers.contains(connectToUser)){
					output.writeUTF("connected");
					output.flush();
					System.out.println(userDetails);

					ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
					oos.flush();
					oos.writeObject(ServerThread.publicKeysList.get(ServerThread.activeUsers.indexOf(connectToUser)));
					oos.flush();
					message = user+";"+token+";"+userDetails.get(0)+";"+userDetails.get(1)+";"+userDetails.get(2)+";" +getDateTime();
					System.out.println("user is  "+ user);

					connOtherClient(clientDetails.get(2),clientDetails.get(0),message);

				}
			}
		}catch(Exception e){
			System.out.println(e);
			//closeDBConn();
		}
	}

	public void decryption(byte[] cipherText, String timeString)throws Exception {

		System.out.println("start of decryption");
		System.out.println("mesage before decrytion method in bytes" +cipherText);
		byte[] decipheredMessage = decrypt(cipherText, serverKey.getPrivate());

		System.out.println(String.format("The plaintext decripted on server side is : %s", decipheredMessage));
		String x = new String(decipheredMessage);
		String result =  x.substring(0,x.indexOf('['));
		String signTimestamp =  x.substring(x.indexOf('['));
		String sign =signTimestamp.substring(0, 11);
		String Timestamp =signTimestamp.substring(11);
		//String res = new String(result);

		System.out.println("result...."+result);
		System.out.println("sign..."+sign);
		System.out.println("Timestamp..."+Timestamp);
		System.out.println("timeString.."+timeString);

		long sub1 = Long.parseLong(Timestamp.substring(0,(Timestamp.length())/2));
		long sub2 = Long.parseLong(Timestamp.substring((Timestamp.length())/2));
		long s1 = Long.parseLong(timeString.substring(0,(timeString.length())/2));
		long s2 = Long.parseLong(timeString.substring((timeString.length())/2));

		if (s1-sub1 ==0){
			if (s2-sub2 > 1000){
				System.out.println("Replayed message");
				//showMessage("Replayed Attack");
				closeConn();
			}
			else{
				System.out.println(s2-sub2);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
			//showMessage("Replayed Attack");
			closeConn();
		}
		int length1 = input.readInt();
		byte[] signature = null;
		if(length1>0) {
			signature = new byte[length1];
			input.readFully(signature, 0, signature.length); // read the message
		}


		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(clientPublicKey);
		publicSignature.update(result.getBytes());


		boolean check = publicSignature.verify(signature);
		System.out.println("check"+check);

//		System.out.println("here");
		output.flush();

	}

	public void encryption(String plainText) throws Exception {

		Signature signatureProvider = null;
		signatureProvider = Signature.getInstance("SHA256WithRSA");
		signatureProvider.initSign(serverKey.getPrivate());
		signatureProvider.update(plainText.getBytes());
		byte[] signature = signatureProvider.sign();

		String y = signature.toString();
		String timeString = Long.toString(new Date().getTime());
		System.out.println("timeString.."+timeString);

		Cipher encCipher = null;
		encCipher = Cipher.getInstance("RSA");
		encCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);

		byte[] encrypted = encCipher.doFinal((plainText+y+timeString).getBytes());

		output.writeInt(encrypted.length);
		output.write(encrypted);
		output.flush();

		System.out.println("signature"+signature);
		System.out.println("length" +signature.length);
		output.writeInt(signature.length);
		output.write(signature);
		output.flush();

//		System.out.println("here");
	}

	public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws Exception {
		System.out.println("start of decryption method");
		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] x = decriptCipher.doFinal(encrypted);
		System.out.println("end of decryption method");
		System.out.println(x);
		return x;
	}
	private String generateToken(){
		String uuid = UUID.randomUUID().toString();
		return uuid;
	}

	private String getDateTime(){
		SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date date = new Date();
		return formatter.format(date);
	}

	private void addToActiveUsersList(String username){
		if (!ServerThread.activeUsers.contains(username)){
			ServerThread.activeUsers.add(username);
			ServerThread.publicKeysList.add(clientPublicKey);
			user=username;
		}
		System.out.println(ServerThread.activeUsers);
		System.out.println(ServerThread.publicKeysList);
	}

	private void closeDBConn(){

		try { rs.close(); } catch (Exception e) { System.out.println(e);}
		try { stmt.close(); } catch (Exception e) { System.out.println(e); }
		try { conn.close(); } catch (Exception e) { System.out.println(e); }
		System.out.println("DB CLOSED");
	}

	private ArrayList<String> findUserDetails(ResultSet rs) throws SQLException {

		ArrayList<String> clientDetails = new ArrayList<String>();
		while (rs.next()) {
			clientDetails.add(Integer.toString( rs.getInt("PORT")));
			clientDetails.add(rs.getString("PUBLIC_KEY"));
			clientDetails.add(rs.getString("ADDRESS"));
			//System.out.println(port+"," + address+"," + publicKeyClient);
		}

		return clientDetails;
	}

	private void connOtherClient(String host, String port, String message) throws Exception {
		output.close();
		input.close();
		System.out.println("host and port"+ host.substring(1)+","+port);
		connection = new Socket(InetAddress.getByName(host.substring(1)), Integer.parseInt(port));

		setupStreams();
		System.out.println(connection);
		try{
			System.out.println("message being sent is :: "+message);
			output.writeUTF(message);
			System.out.println("message sent");

			ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
			oos.writeObject(ServerThread.publicKeysList.get(ServerThread.activeUsers.indexOf(user)));

			System.out.println(user+"..."+ServerThread.publicKeysList.get(ServerThread.activeUsers.indexOf(user)));
			oos.flush();

		}catch(Exception e){
			output.close();
			input.close();
			connection.close();
		}
	}

}