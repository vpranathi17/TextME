import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

public class Client extends JFrame{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static JTextField userText;
	static JTextArea chatWindow;
    private static DataOutputStream output;
    private static DataInputStream input;
    private static String serverIP;
    private static Socket connection;
    static PublicKey serverPublicKey;

	static Connections con = new Connections();
	chatWindow chat;
    static String message ="";	
    String username = "";
	String password = "";
	String email = "";
	String connect_user = "";
	
	String[] info;

    //constructor
    public Client(String host) throws ClassNotFoundException, InvocationTargetException, InterruptedException{
    	serverIP = host;
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
        setVisible(false);
    }

    public void running() throws Exception {
       
        	chatWin();
        	System.out.println("I am here");
        	//connectServer();
        
    }
    
    public void chatWin() throws Exception {
        String[] options = new String[] {"SignUp", "SignIn", "Cancel"};
    	int reply = JOptionPane.showOptionDialog(null, "Welcome to TextME application", "TextME", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
    	        null, options, options[0]);
        System.out.println(reply);
        if (reply == 1){
        	signin_frame();
        }
        else{
        	if(reply == 0){
        		signup_frame();
        	}
        	else{
        		JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "Information",JOptionPane.INFORMATION_MESSAGE);
        	}
        }
	}
    
    private void signin_frame() throws Exception {
    	 username = JOptionPane.showInputDialog("Please enter the username");
    	 password = JOptionPane.showInputDialog("Please enter the password");
     	connectServer();
    	 infoExchange(username,password,"","Sign In");
	}
    
    private void signup_frame() throws Exception {
    	email = JOptionPane.showInputDialog("Please enter the email id");
    	username = JOptionPane.showInputDialog("Please enter the username");
    	password = JOptionPane.showInputDialog("Please enter the password");
    	connectServer();
   	 	infoExchange(username,password,email,"Sign In");
    }

	private void connectServer() throws IOException {
        showMessage("Connecting....\n");
        connection = new Socket(InetAddress.getByName(serverIP), 5000);
        showMessage("Connected to :: " + connection.getInetAddress().getHostName());
    }
	
   private void infoExchange(String username, String password, String email, String info) throws Exception{
	   	ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
   		serverPublicKey = (PublicKey) ois.readObject();
   		System.out.println(serverPublicKey);
   	
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal(username.getBytes());
		byte[] cipherText1 = cipher.doFinal(password.getBytes());
		byte[] cipherText2 = cipher.doFinal(email.getBytes());
		byte[] cipherText3 = cipher.doFinal(info.getBytes());
		
   		DataOutputStream dos1 = new DataOutputStream(connection.getOutputStream());
   		dos1.writeInt(cipherText.length);
        dos1.write(cipherText);
        
        DataOutputStream dos2 = new DataOutputStream(connection.getOutputStream());
        dos2.writeInt(cipherText1.length);
        dos2.write(cipherText1);
        
        DataOutputStream dos3 = new DataOutputStream(connection.getOutputStream());
        dos3.writeInt(cipherText2.length);
        dos3.write(cipherText2);
        
        DataOutputStream dos4 = new DataOutputStream(connection.getOutputStream());
        dos4.writeInt(cipherText3.length);
        dos4.write(cipherText3);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair clientKey = keyGen.generateKeyPair();
		
        ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
        oos.writeObject(clientKey.getPublic());
		oos.flush();
       
        System.out.println("Sent details are...");
        System.out.println(cipherText);
        System.out.println(cipherText1);
        System.out.println(cipherText2);
        System.out.println(cipherText3);
        System.out.println(clientKey.getPublic());
        
        dos1.flush();
        dos2.flush();
        oos.flush();
        databaseCheck();
	}
   
   private void databaseCheck() throws Exception{
	   DataInputStream dis = new DataInputStream(connection.getInputStream());
	   String rmsg = dis.readUTF();
	   System.out.println(rmsg);
	   if (rmsg.equals("OK")){
			JOptionPane.showMessageDialog(null," Everything is fine!","Information",JOptionPane.INFORMATION_MESSAGE);
			connect_user = JOptionPane.showInputDialog("Please enter the username");
			connectionCheck(connect_user);
	   }
	   else{
		   if (rmsg.equals("Exists")){
				JOptionPane.showMessageDialog(null," User already exists!","Information",JOptionPane.INFORMATION_MESSAGE);
		   }
		   else {
			   if (rmsg.equals("Not Cool")){
					JOptionPane.showMessageDialog(null,"Please enter valid credentials!","Error",JOptionPane.ERROR_MESSAGE);
			   }
			   else{
				   if(rmsg.equals("Inserted")){
						JOptionPane.showMessageDialog(null," New user created!","Information",JOptionPane.INFORMATION_MESSAGE); 
						connect_user = JOptionPane.showInputDialog("Please enter the username");
						connectionCheck(connect_user);
				   }else{
						JOptionPane.showMessageDialog(null," Something went wrong!","Error",JOptionPane.ERROR_MESSAGE);     
				   }
			   }
		   }
	   }
   }
   
	public void connectionCheck(String username) throws Exception {
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
	        setupStreams();
	        whileChatting();
        }
        else{
			JOptionPane.showMessageDialog(null," Enter valid username for connection!","Error",JOptionPane.ERROR_MESSAGE);
        }
	}

    public void setupStreams()throws IOException, ClassNotFoundException{
        input = new DataInputStream(connection.getInputStream());
        output = new DataOutputStream(connection.getOutputStream());
        output.flush();
        showMessage("\n conn streams setup");
        System.out.println("In show up streams");
        setVisible(true);
    }

    public void whileChatting()throws IOException, ClassNotFoundException{
        // during the chat conversation
		setVisible(true);
    	showMessage("\n whileChatting setup");
                        do{
                        	try {
                        		message = input.readUTF();
                        		System.out.println(message);
                                showMessage("\n" + message);
							} catch (IOException e) {
								e.printStackTrace();
							}
                        }while(!message.equals("SERVER_END"));      
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
        }
    }

    static void showMessage(final String text) {
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                        chatWindow.append(text);
                    }
                }
        );
    }

    static void ableToType(final boolean tof){
    	System.out.println("In able to type");
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                    	userText.setEditable(tof);
                    }

                }
        );
    }
}