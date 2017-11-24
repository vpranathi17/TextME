import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Client extends JFrame{
	static JTextField userText;
	static JTextArea chatWindow;
    private static DataOutputStream output;
    private static DataInputStream input;
    private String serverIP;
    private static Socket connection;
    static String username = "";
    static String password = "";
    static PublicKey serverPublicKey;

	static Connections con = new Connections();
    static String message ="";

    //constructor
    public Client(String host){serverIP = host;
    	setTitle("Client Chat Window");
        serverIP = host;
        userText = new JTextField();
        userText.setFont(new Font("courier", Font.PLAIN, 25));
        userText.setEditable(false);
        userText.addActionListener(
                new ActionListener(){
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        try {
							sendData(e.getActionCommand());
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						} catch (ClassNotFoundException e1) {
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
        add(new JScrollPane(chatWindow), BorderLayout.CENTER);
        setSize(300,150);
        setVisible(true);
    }

    public void running() throws ClassNotFoundException {
        try{
            connectServer();
            setUIDesign();
        }catch(EOFException eof){
           showMessage("\n connection terminated");
        }catch(IOException io){
            io.printStackTrace();
        }
    }

	private void connectServer() throws IOException {
        showMessage("Connecting....\n");
        connection = new Socket(InetAddress.getByName(serverIP), 5000);
        showMessage("Connected to :: " + connection.getInetAddress().getHostName());
    }

	private void setUIDesign(){

    	frame f = new frame();
    	f.setVisible(true);
	}
	
   static void infoExchange(String username, String password, String info)throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
   		ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
   		serverPublicKey = (PublicKey) ois.readObject();
   		System.out.println(serverPublicKey);
   	
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal(username.getBytes());
		byte[] cipherText1 = cipher.doFinal(password.getBytes());
		byte[] cipherText2 = cipher.doFinal(info.getBytes());
		
   		DataOutputStream dos1 = new DataOutputStream(connection.getOutputStream());
   		dos1.writeInt(cipherText.length);
        dos1.write(cipherText);
        
        DataOutputStream dos2 = new DataOutputStream(connection.getOutputStream());
        dos2.writeInt(cipherText1.length);
        dos2.write(cipherText1);
        
        DataOutputStream dos3 = new DataOutputStream(connection.getOutputStream());
        dos3.writeInt(cipherText2.length);
        dos3.write(cipherText2);     
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair clientKey = keyGen.generateKeyPair();
		
        ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
        oos.writeObject(clientKey.getPublic());
		oos.flush();
       
        System.out.println("Sent details are...");
        System.out.println(cipherText);
        System.out.println(cipherText1);
        System.out.println(clientKey.getPublic());
        
        dos1.flush();
        dos2.flush();
        oos.flush();
        databaseCheck();
	}
   
   private static void databaseCheck() throws IOException{
	   DataInputStream dis = new DataInputStream(connection.getInputStream());
	   String rmsg = dis.readUTF();
	   if (rmsg.equals("OK")){
			JOptionPane.showMessageDialog(null," Everything is fine!","Information",JOptionPane.INFORMATION_MESSAGE);
			con.setVisible(true);
	   }
	   else{
		   if (rmsg.equals("Exists")){
				JOptionPane.showMessageDialog(null," Username already exists!","Information",JOptionPane.INFORMATION_MESSAGE);
		   }
		   else {
			   if (rmsg.equals("Not Cool")){
					JOptionPane.showMessageDialog(null,"Please enter valid credentials!","Error",JOptionPane.ERROR_MESSAGE);
			   }
			   else{
				   if(rmsg.equals("Inserted")){
						JOptionPane.showMessageDialog(null," New user created!","Information",JOptionPane.INFORMATION_MESSAGE);   
				   }else{
						JOptionPane.showMessageDialog(null," Something went wrong!","Error",JOptionPane.ERROR_MESSAGE);     
				   }
			   }
		   }
	   }
   }
   
	public static void connectionCheck(String username) throws Exception {
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal(username.getBytes());
		
   		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
   		dos.writeInt(cipherText.length);
        dos.write(cipherText);
        System.out.println(cipherText);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        String rmsg = dis.readUTF();
        if (rmsg.equals("Connected")){
			JOptionPane.showMessageDialog(null," Connected!","Information",JOptionPane.INFORMATION_MESSAGE);
	        ableToType(true);
			con.setVisible(false);
			setupStreams();
        }
        else{
			JOptionPane.showMessageDialog(null," Enter valid username for connection!","Error",JOptionPane.ERROR_MESSAGE);
			con.setVisible(false);
        }
	}
	public static void run() throws IOException, ClassNotFoundException{		
			try {
				whileChatting();
			}	catch(Exception e){
				showMessage("\n don't know what's happening!");
			}
			finally{
				closeConn();
			}
	}

    static void setupStreams()throws IOException, ClassNotFoundException{
        input = new DataInputStream(connection.getInputStream());
        output = new DataOutputStream(connection.getOutputStream());
        output.flush();
        showMessage("\n conn streams setup");
        whileChatting();
    }

    static void whileChatting()throws IOException, ClassNotFoundException{
        // during the chat conversation
                        //do{
                        	try {
                        		message = input.readUTF();
                                showMessage("\n" + message);
							} catch (IOException e) {
								e.printStackTrace();
							}
                        //}while(!message.equals("SERVER_END"));      
    }

    private static void closeConn(){
        showMessage("\n Bye Bye Server's out!! ");
        ableToType(false);

        try{
            output.close();
            input.close();
            connection.close();
        }catch(IOException io){
            io.printStackTrace();
        }
    }
    static void sendData(String message) throws IOException, ClassNotFoundException{
        try{
            output.writeUTF("CLIENT - " + message);
            output.flush();
            showMessage("\nCLIENT - "+message);
        }catch(IOException io){
        	io.printStackTrace();
        }whileChatting();
    }
    static void showMessage(final String text) {
        //whileChatting();
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                        chatWindow.append(text);
                    }
                }
        );
    }

    static void ableToType(final boolean tof){
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                    	userText.setEditable(tof);
                    }

                }
        );
    }
}
