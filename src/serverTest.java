import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class ServerThread implements Runnable {
    private final ServerSocket serverSocket;
    private final ExecutorService pool;
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
    DataInputStream dis1;
    DataInputStream dis2;
    DataInputStream dis3;
    DataInputStream dis4;
	static java.sql.Connection conn = null;
	static Statement stmt;
	KeyPair serverKey;
	PublicKey clientPublicKey;
	//ArrayList<String> activeusers = new ArrayList<String>();
	//ArrayList<Socket> users = new ArrayList<Socket>();
	
    Handler(Socket connection) { this.connection = connection; } //Handler(int port){server = new serverSocket(port); connection = server.accept(); users.add(connection);}
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
                        //sendMessage(userText.getText());
                    	try {
                    		showMessage("\nSERVER -" + userText.getText());
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
        chatWindow.setBounds(20,20, 500,500);
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

    	dis1 = new DataInputStream(connection.getInputStream());
		int length = dis1.readInt();
		
		byte[] cipherText = null;
		if(length>0) {
			cipherText = new byte[length];
		    dis1.readFully(cipherText, 0, cipherText.length); 
		}
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String username = new String(cipher.doFinal(cipherText));
		
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
		String password = sb.toString();
		
    	dis3 = new DataInputStream(connection.getInputStream());
		int length2 = dis3.readInt();
		
		byte[] cipherText2 = null;
		if(length2>0) {
			cipherText2 = new byte[length2];
		    dis3.readFully(cipherText2, 0, cipherText2.length); 
		}
		
		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String email = new String(cipher2.doFinal(cipherText2));
		
    	dis4 = new DataInputStream(connection.getInputStream());
		int length3 = dis4.readInt();
		
		byte[] cipherText3 = null;
		if(length3>0) {
			cipherText3 = new byte[length3];
		    dis4.readFully(cipherText3, 0, cipherText3.length); 
		}
		
		Cipher cipher3 = Cipher.getInstance("RSA");
		cipher3.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String info = new String(cipher3.doFinal(cipherText3));
    	
    	ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
    	clientPublicKey = (PublicKey) ois.readObject();

		//System.out.println(cipherText);
//		System.out.println(cipherText1);
//		System.out.println(cipherText2);
//		System.out.println(cipherText3);
//
//    	System.out.println(username);
//    	System.out.println(password);
//    	System.out.println(email);
//    	System.out.println(info);
//    	System.out.println(clientPublicKey);
    	InetAddress inet = connection.getInetAddress();
    	int portNum = connection.getPort();
    	System.out.println(inet+":"+ portNum);
    	databaseCheck(username,password,clientPublicKey,info,inet,portNum,email);
    	}
  
  	private void databaseCheck(String username, String password, PublicKey clientPublicKey, String info, InetAddress inet, int portNum, String email) throws Exception{
  		String msg = "";
		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
  		String url = ("jdbc:sqlite:/Users/Darshana/Desktop/test.db");	
		conn = DriverManager.getConnection(url);
		stmt = conn.createStatement();
		String sql = ("SELECT USERNAME FROM LOGIN WHERE USERNAME ='"+username+"'");
		//PreparedStatement pstmt = conn.prepareStatement( sql );
		 
		ResultSet rs = stmt.executeQuery(sql);
		if (rs.next())
		{
			String seq = ("SELECT PASSWORD FROM LOGIN WHERE PASSWORD='"+password+"'");
			//PreparedStatement pstmt1 = conn.prepareStatement( sql );
        	ResultSet res = stmt.executeQuery(seq);
        	if (res.next() && info.equals("Sign In")) {//username exists, password exists, Sign in
        		msg = "OK";
        		dos.writeUTF(msg);
        		String sq = ("UPDATE LOGIN SET ADDRESS = '"+inet+"', PORT = '"+portNum+"' WHERE USERNAME = '"+username+"'");
        		stmt.execute(sq);
        		//activeusers.add(username);
        		connectionCheck();
        	}
        	else{
        		if (info.equals("Sign Up")){//username exists, password doesn't exists, Sign up
        			//username exists, password exists, Sign up
        		msg = "Exists";
        		}
        		else{// username exists, password doesn't exists, Sign in
        			msg = "Not Cool";
        		}
        		dos.writeUTF(msg);
        	}
		}
		else{//username doesn't exists
			String seq = ("SELECT EMAIL_ID FROM LOGIN WHERE EMAIL_ID='"+email+"'");
			ResultSet res = stmt.executeQuery(seq);//returns false even if data exists
			if (!res.next()){//email doesn't exists
				if (info.equals("Sign Up") ){//Sign up and email is new
				    String seql = ("INSERT INTO LOGIN (USERNAME,PASSWORD,PUBLIC_KEY,ADDRESS,PORT,EMAIL_ID) " +
		                       "VALUES('"+username+"','"+password+"','"+clientPublicKey+"','"+inet+"','"+portNum+"','"+email+"')"); 
				    stmt.execute(seql);
				    msg = "Inserted";
				}
				else{
					msg = "Not Cool";
				}
			}
			
			else{//email exists
				msg = "Exists";
				}
			dos.writeUTF(msg);
//			System.out.println(msg);
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
		String sql = ("SELECT USERNAME FROM LOGIN WHERE USERNAME ='"+username+"'");
		ResultSet rs = stmt.executeQuery(sql);
		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
		if(!rs.next()){//no such user
			String msg = "Impossible";
			dos.writeUTF(msg);
			connectionCheck();
		}
		else{//registered user
			//if (activeusers.contains(username)){//active user
				String msg = "Connected";
				dos.writeUTF(msg);
				setupStreams();
//				}
//			else{//inactive
//				String msg = "Not Connected";
//				dos.writeUTF(msg);
//				connectionCheck();
//			}
		}
	}
	private void setupStreams()throws Exception{
		setVisible(true);
        output = new DataOutputStream(connection.getOutputStream());
        output.flush();
        input = new DataInputStream(connection.getInputStream());
        showMessage("conn streams setup");
        whileChatting();
    }

    private void closeConn() throws SQLException{
        showMessage("\n Bye Bye Server's out!! ");
        ableToType(false);

        try{
        	conn.close();
        	dis1.close();
        	dis2.close();
            output.close();
            input.close();
            connection.close();
        }catch(IOException io){
            io.printStackTrace();
        }
    }

   /* private void sendMessage(String message){

        try{
        	output.writeUTF("SERVER -" + message);
            output.flush();
            showMessage("\nSERVER - " + message);
        }catch(IOException io){
            chatWindow.append("\n ERROR: cant't send this message");
        }

    }*/

    private void showMessage(final String text){
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                        chatWindow.append(text);
                    }

                }
        );
    }

    private void ableToType(final boolean tof){
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                        userText.setEditable(tof);
                    }

                }
        );
    }

    private void whileChatting()throws Exception{
        // during the chat conversation
        String message = "You are now connected! ";
       // sendMessage(message);
        ableToType(true);
        do{
            System.out.println(connection.getRemoteSocketAddress().toString());
            
          //DataInputStream dis = new DataInputStream(connection.getInputStream());
    		int length = input.readInt();
    		
    		byte[] cipherText = null;
    		if(length>0) {
    			cipherText = new byte[length];
    		    input.readFully(cipherText, 0, cipherText.length); // read the message
    		}
         //message = (String) input.readUTF();
         System.out.println(cipherText);
         decryption(cipherText);
			//showMessage("\n" + message);
			//showMessage("Don't know what's happening!!!");
        }while(!message.equals("CLIENT_END"));
    }
    
	public void decryption(byte[] cipherText)throws Exception {
		
		System.out.println("start of decryption");
		System.out.println("mesage before decrytion method in bytes" +cipherText);
		byte[] decipheredMessage = decrypt(cipherText, serverKey.getPrivate());
		
		System.out.println(String.format("The plaintext decripted on server side is : %s", decipheredMessage));
		String x = new String(decipheredMessage);
		String result =  x.substring(0,x.indexOf('['));
		String sign =  x.substring(x.indexOf('['));
		
		//String res = new String(result);
		
		System.out.println("result"+result);
		System.out.println("sign"+sign);	
		
		//System.out.println(sign.length);
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
		
		//DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
		System.out.println("here");
//		output.writeUTF(result);
//		if(check) {
//			output.writeUTF("yes");
//		}else{
//			output.writeUTF("no");
//		}
		showMessage("\n"+"CLIENT-"+result);
		output.flush();
		
	}
	
public void encryption(String plainText) throws Exception {
		
        Signature signatureProvider = null;
        signatureProvider = Signature.getInstance("SHA256WithRSA");
        signatureProvider.initSign(serverKey.getPrivate());
        signatureProvider.update(plainText.getBytes());
        byte[] signature = signatureProvider.sign();	
        
        String y = signature.toString();
        
        Cipher encCipher = null;
        encCipher = Cipher.getInstance("RSA");
        encCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        
        byte[] encrypted = encCipher.doFinal((plainText+y).getBytes());
        
       output.writeInt(encrypted.length);
		output.write(encrypted);
		output.flush();
       	  
		System.out.println("signature"+signature);
		System.out.println("length" +signature.length);
		output.writeInt(signature.length);
		output.write(signature);
		output.flush();
		
		System.out.println("here");
		//DataInputStream dis = new DataInputStream(connection.getInputStream());
//		String result = input.readUTF();
//		System.out.println("The result returned by server is : " + result);
//		String result2 = input.readUTF();
//		System.out.println("The integrity of message is checked with " + result2);

		//input.close();
		//showMessage("\nCLIENT - "+plainText);
		//connection.close();
        
        
    }
	
	public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws Exception {
		System.out.println("start of decryption method");
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] x = decriptCipher.doFinal(encrypted);
        System.out.println("end of decryption method");
        return x;
    }
}