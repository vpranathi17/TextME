import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
	static java.sql.Connection conn = null;
	static Statement stmt;
	KeyPair serverKey;
	
    Handler(Socket connection) { this.connection = connection; }
    public void run() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(0,0,500,500);
		setUI();
		try {
			infoExchange();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }

    private void setUI(){
        setTitle("Messenger");
        userText= new JTextField();
        userText.setFont(new Font("courier", Font.PLAIN, 25));
        userText.setEditable(false);
        userText.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        sendMessage(userText.getText());
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
        setVisible(true);

    }
    
  private void infoExchange()throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SQLException{
      	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		serverKey = keyGen.generateKeyPair();
		
		ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
		oos.writeObject(serverKey.getPublic());
		oos.flush();

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
		String password = new String(cipher1.doFinal(cipherText1));
		
    	dis3 = new DataInputStream(connection.getInputStream());
		int length2 = dis3.readInt();
		
		byte[] cipherText2 = null;
		if(length2>0) {
			cipherText2 = new byte[length2];
		    dis3.readFully(cipherText2, 0, cipherText2.length); 
		}
		
		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String info = new String(cipher2.doFinal(cipherText2));
    	
    	ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
    	PublicKey clientPublicKey = (PublicKey) ois.readObject();
    	
    	System.out.println(username);
    	System.out.println(password);
    	System.out.println(info);
    	System.out.println(clientPublicKey);
    	databaseCheck(username,password,clientPublicKey,info);
    	}
  
  	private void databaseCheck(String username, String password, PublicKey clientPublicKey, String info) throws SQLException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
  		String msg = "";
		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
  		String url = ("jdbc:sqlite:/Users/PranathiVasireddy/Desktop/sqlite/test.db");	
		conn = DriverManager.getConnection(url);
		stmt = conn.createStatement();
		String sql = ("SELECT USERNAME FROM LOGIN WHERE USERNAME ='"+username+"'");
		ResultSet rs = stmt.executeQuery(sql);
		if (rs.next())
		{
			String seq = ("SELECT PASSWORD FROM LOGIN WHERE PASSWORD='"+password+"'");
        	ResultSet res = stmt.executeQuery(seq);
        	if (res.next() && info.equals("Sign In")) {//username exists, password exists, Sign in
        		msg = "OK";
        		dos.writeUTF(msg);
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
			if (info.equals("Sign Up")){
			    String seq = ("INSERT INTO LOGIN (USERNAME,PASSWORD,PUBLIC_KEY) " +
	                       "VALUES('"+username+"','"+password+"','"+clientPublicKey+"')"); 
			    stmt.execute(seq);
			    msg = "Inserted";
			}
			else{
				msg = "Not Cool";
			}
			dos.writeUTF(msg);
		}
  	}

    private void connectionCheck() throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SQLException {
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
		if(!rs.next()){
			String msg = "Impossible";
			dos.writeUTF(msg);
		}
		else{
			String msg = "Connected";
			dos.writeUTF(msg);
			setupStreams();
		}
	}
	private void setupStreams()throws IOException{
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

    private void sendMessage(String message){

        try{
        	output.writeUTF("SERVER -" + message);
            output.flush();
            showMessage("\nSERVER - " + message);
        }catch(IOException io){
            chatWindow.append("\n ERROR: cant't send this message");
        }

    }

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

    private void whileChatting()throws IOException{
        // during the chat conversation
        String message = "You are now connected! ";
        sendMessage(message);
        ableToType(true);
        do{
            System.out.print(connection.getRemoteSocketAddress().toString());
         message = (String) input.readUTF();
			showMessage("\n" + message);
			//showMessage("Don't know what's happening!!!");
        }while(!message.equals("CLIENT_END"));
    }
}