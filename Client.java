import javax.crypto.Cipher;
import javax.imageio.ImageIO;
import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
    }
    
    public void chatWin() throws Exception {
    	ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
        String[] options = new String[] {"SignUp", "SignIn", "Cancel"};
    	int reply = JOptionPane.showOptionDialog(null, "Welcome to TextME application", "TextME", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
    			 img, options, options[0]);
        if (reply == 1){
        	signin_frame();
        }
        else{
        	if(reply == 0){
        		signup_frame();
        	}
        	else{
        		JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "TextME",JOptionPane.INFORMATION_MESSAGE,img);
        	}
        }
	}
    
    private void signin_frame() throws Exception {
    	ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
        JTextField Username = new JTextField(5);
        JPasswordField Password = new JPasswordField(5);

        JPanel myPanel = new JPanel();
        myPanel.add(new JLabel("Username:"));
        myPanel.add(Username);
        myPanel.add(Box.createHorizontalStrut(15)); // a spacer
        myPanel.add(new JLabel("Password:"));
        myPanel.add(Password);

        int result = JOptionPane.showConfirmDialog(null, myPanel, 
                 "Please Enter username and password", JOptionPane.DEFAULT_OPTION, JOptionPane.OK_CANCEL_OPTION,img);
        if (result == 0){
        	username = Username.getText();
        	char[] pass = Password.getPassword();
        	password = String.valueOf(Password.getPassword());
         	connectServer();
        	 infoExchange(username,password,"","Sign In");
        }
	}
    
    private void signup_frame() throws Exception {
    	ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
        JTextField Username = new JTextField(5);
        JPasswordField Password = new JPasswordField(5);
        JTextField Emailid = new JTextField(20);

        JPanel myPanel = new JPanel();
        myPanel.add(Box.createHorizontalStrut(30)); // a spacer
        myPanel.add(new JLabel("Email id:"));
        myPanel.add(Emailid);
        myPanel.add(new JLabel("Username:"));
        myPanel.add(Username);
        myPanel.add(Box.createHorizontalStrut(15)); // a spacer
        myPanel.add(new JLabel("Password:"));
        myPanel.add(Password);
        int result = JOptionPane.showConfirmDialog(null, myPanel, 
                "Please Enter email id, username and password", JOptionPane.DEFAULT_OPTION, JOptionPane.OK_CANCEL_OPTION,img);
       if (result == 0){
       	email = Emailid.getText();
    	username = Username.getText();
       	password = String.valueOf(Password.getPassword());
    	connectServer();
   	 	infoExchange(username,password,email,"Sign Up");
       }
    }

	private void connectServer() throws IOException {
        showMessage("Connecting....\n");
        connection = new Socket(InetAddress.getByName(serverIP), 80);
        showMessage("Connected to :: " + connection.getInetAddress().getHostName());
    }
	
   private void infoExchange(String username, String password, String email, String info) throws Exception{
	   	ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
   		serverPublicKey = (PublicKey) ois.readObject();
   		System.out.println(serverPublicKey);

        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());

        byte pass[] = md.digest();

        //convert the byte to hex format 
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < pass.length; i++) {
         sb.append(Integer.toString((pass[i] & 0xff) + 0x100, 16).substring(1));
        }

        //System.out.println("Hex format : " + sb.toString());
        byte[] b = new BigInteger(sb.toString(),16).toByteArray();
        //System.out.println(b);
   		
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal(username.getBytes());
		byte[] cipherText1 = cipher.doFinal(b);
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
       
		//System.out.println("Sent details are...");
		//System.out.println(cipherText);
        //System.out.println(cipherText1);
        //System.out.println(cipherText2);
        //System.out.println(cipherText3);
        //System.out.println(clientKey.getPublic());
        
        dos1.flush();
        dos2.flush();
        oos.flush();
        databaseCheck();
	}
   
   private void databaseCheck() throws Exception{
	   DataInputStream dis = new DataInputStream(connection.getInputStream());
	   String rmsg = dis.readUTF();
	   //System.out.println(rmsg);
	   if (rmsg.equals("OK")){
		   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/sign-check-icon.png");
			JOptionPane.showMessageDialog(null," Everything is fine!","TextME",JOptionPane.INFORMATION_MESSAGE,img);
			connections();
	   }
	   else{
		   if (rmsg.equals("Exists")){
			   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/images.jpeg");
				JOptionPane.showMessageDialog(null," User already exists!","TextME",JOptionPane.INFORMATION_MESSAGE,img);
				chatWin();
		   }
		   else {
			   if (rmsg.equals("Not Cool")){
				   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
					JOptionPane.showMessageDialog(null,"Please enter valid credentials!","TextME",JOptionPane.ERROR_MESSAGE,img);
					chatWin();
			   }
			   else{
				   if(rmsg.equals("Inserted")){
					   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/svfzpeepadzijwotnacu.gif");
						JOptionPane.showMessageDialog(null," New user created!","TextME",JOptionPane.INFORMATION_MESSAGE,img); 
						chatWin();
				   }else{
					   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
						JOptionPane.showMessageDialog(null," Something went wrong!","TextME",JOptionPane.ERROR_MESSAGE,img);
						chatWin();
				   }
			   }
		   }
	   }
   }
   
   private void connections() throws Exception{
	   JTextField user = new JTextField(5);
       JPanel myPanel = new JPanel();
       myPanel.add(new JLabel("Username:"));
       myPanel.add(user);
	   ImageIcon icon = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
		int result = JOptionPane.showConfirmDialog(null, myPanel, 
               "Please enter the username you want to connect to:", JOptionPane.DEFAULT_OPTION, JOptionPane.OK_CANCEL_OPTION,icon);;
	       //System.out.println(result);
	       if (result == 0){
	       	connect_user=user.getText();
		connectionCheck(connect_user);
	       }
   }
   
	public void connectionCheck(String username) throws Exception {
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal(username.getBytes());
		
   		DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
   		dos.writeInt(cipherText.length);
        dos.write(cipherText);
        //System.out.println(cipherText);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        String rmsg = dis.readUTF();
        if (rmsg.equals("Connected")){
 		   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/sign-check-icon.png");
			JOptionPane.showMessageDialog(null," Connected!","TextME",JOptionPane.INFORMATION_MESSAGE,img);
	        ableToType(true);
	        setupStreams();
	        whileChatting();
        }
        else{
        	if(rmsg.equals("Not Connected")){
				   	ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/svfzpeepadzijwotnacu.gif");
					JOptionPane.showMessageDialog(null," User requested is not active now!","TextME",JOptionPane.INFORMATION_MESSAGE,img); 
					connections();
        	}
        	else{
 			   ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
 			   JOptionPane.showMessageDialog(null," Enter valid username for connection!","TextME",JOptionPane.ERROR_MESSAGE,img);
 			   connections();
        	}
        }
	}

    public void setupStreams()throws IOException, ClassNotFoundException{
        setVisible(true);
        input = new DataInputStream(connection.getInputStream());
        output = new DataOutputStream(connection.getOutputStream());
        output.flush();
        showMessage("\n conn streams setup");
        System.out.println("In show up streams");
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