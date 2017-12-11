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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Date;

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
    static KeyPair clientKey;
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
                    public void actionPerformed(ActionEvent e) {
                        try {                        		
                        	String message = e.getActionCommand();
                        	showMessage("\nCLIENT - "+message);
                        	encryption(message);
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						} catch (ClassNotFoundException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
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
        add(new JScrollPane(chatWindow), BorderLayout.CENTER);
        JButton end =  new JButton("END");
        end.addActionListener(new ActionListener(){
        	public void actionPerformed(ActionEvent e) {
        			try {
						closeConn();
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        	}
        );
        add(end, BorderLayout.SOUTH);
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
        myPanel.setName("TextME");
        myPanel.add(new JLabel("Username:"));
        myPanel.add(Username);
        myPanel.add(Box.createHorizontalStrut(15)); // a spacer
        myPanel.add(new JLabel("Password:"));
        myPanel.add(Password);

        int result = JOptionPane.showConfirmDialog(null, myPanel, 
                 "TextME",JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, img);
        if (result == 0){
        	username = Username.getText();
        	char[] pass = Password.getPassword();
        	password = String.valueOf(pass);
         	connectServer();
        	 infoExchange(username,password,"","Sign In");
        }
        else{
    		JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "TextME",JOptionPane.INFORMATION_MESSAGE,img);
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
                "TextME",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE,img);
       if (result == 0){
       	email = Emailid.getText();
    	if (email.matches("[")){
			   ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
				JOptionPane.showMessageDialog(null,"Please enter valid credentials!","TextME",JOptionPane.ERROR_MESSAGE,img1);
				signup_frame();
    	}
    	username = Username.getText();
    	if (username.matches("[")){
			   ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
				JOptionPane.showMessageDialog(null,"Please enter valid credentials!","TextME",JOptionPane.ERROR_MESSAGE,img1);
				signup_frame();
    	}
       	password = String.valueOf(Password.getPassword());
        if (password.matches(".*([A-Z]*.*[0-9]*.*[_.#@$%^&*!]*.)") && password.length()>=8){
        	connectServer();
       	 	infoExchange(username,password,email,"Sign Up");
        }
        else{
			ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
			JOptionPane.showMessageDialog(null," Please choose a strong password!","TextME",JOptionPane.ERROR_MESSAGE,img1);
        	signup_frame();
        }
       }
       else{
   		JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "TextME",JOptionPane.INFORMATION_MESSAGE,img);
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

		String timeString = Long.toString(new Date().getTime());
		System.out.println("timeString.."+timeString);
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());

        byte pass[] = md.digest();

        //convert the byte to hex format 
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < pass.length; i++) {
         sb.append(Integer.toString((pass[i] & 0xff) + 0x100, 16).substring(1));
        }
 
        System.out.println("Hex format : " + sb.toString());
        byte[] b = new BigInteger(sb.toString()+timeString,16).toByteArray();
        System.out.println(b);
		
   		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipherText = cipher.doFinal((username+"["+timeString).getBytes());
		byte[] cipherText1 = cipher.doFinal(b);
		byte[] cipherText2 = cipher.doFinal((email+"["+timeString).getBytes());
		byte[] cipherText3 = cipher.doFinal((info+"["+timeString).getBytes());
		
   		DataOutputStream dos1 = new DataOutputStream(connection.getOutputStream());
   		dos1.writeInt(cipherText.length);
        dos1.write(cipherText);
        
        DataOutputStream dos2 = new DataOutputStream(connection.getOutputStream());
        dos2.writeInt(cipherText1.length);
        System.out.println(cipherText1.length);
        dos2.write(cipherText1);
        
        DataOutputStream dos3 = new DataOutputStream(connection.getOutputStream());
        dos3.writeInt(cipherText2.length);
        dos3.write(cipherText2);
        
        DataOutputStream dos4 = new DataOutputStream(connection.getOutputStream());
        dos4.writeInt(cipherText3.length);
        dos4.write(cipherText3);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		clientKey = keyGen.generateKeyPair();
		
        ObjectOutputStream oos = new ObjectOutputStream(connection.getOutputStream());
        oos.writeObject(clientKey.getPublic());
		oos.flush();
       
		//System.out.println("Sent details are...");
//		System.out.println(cipherText);
//        System.out.println(cipherText1);
//        System.out.println(cipherText2);
//        System.out.println(cipherText3);
//        System.out.println(clientKey.getPublic());
		
		//*****NEW ATTACK CODE*****//
//		AttackerClient attack = new AttackerClient(cipherText,cipherText1,cipherText2,cipherText3);
//        attack.running();
//        closeConn();
        //**STOPPED**//
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
						signin_frame();
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

    public static void encryption(String plainText) throws Exception {
		
        Signature signatureProvider = null;
        signatureProvider = Signature.getInstance("SHA256WithRSA");
        signatureProvider.initSign(clientKey.getPrivate());
        signatureProvider.update(plainText.getBytes());
        byte[] signature = signatureProvider.sign();	
        
        String y = signature.toString();
		
		String timeString = Long.toString(new Date().getTime());
		System.out.println("timeString.."+timeString);
        Cipher encCipher = null;
        encCipher = Cipher.getInstance("RSA");
        encCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        
        byte[] encrypted = encCipher.doFinal((plainText+y+timeString).getBytes());
        
        output.writeInt(encrypted.length);
		output.write(encrypted);
		output.flush();
       	  
		System.out.println("signature"+signature);
		System.out.println("length" +signature.length);
		output.writeInt(signature.length);
		output.write(signature);
		output.flush();
		
		System.out.println("here");
		System.out.println(encrypted);
		System.out.println(InetAddress.getLocalHost());
		
		//DataInputStream dis = new DataInputStream(connection.getInputStream());
//		String result = input.readUTF();
//		System.out.println("The result returned by server is : " + result);
//		String result2 = input.readUTF();
//		System.out.println("The integrity of message is checked with " + result2);
        
        System.out.println(encrypted);
    }
	

	public void whileChatting()throws Exception{
        // during the chat conversation
		setVisible(true);
    	showMessage("\n whileChatting setup");
                        do{
                        	try {
                        		int length = input.readInt();
                        		
                        		byte[] cipherText = null;
                        		if(length>0) {
                        			cipherText = new byte[length];
                        		    input.readFully(cipherText, 0, cipherText.length); // read the message
                        		}
                        		 String timeString = Long.toString(new Date().getTime());
                                 decryption(cipherText, timeString);
                        		System.out.println(message);
                                //showMessage("\n" + message);
							} catch (IOException e) {
								e.printStackTrace();
							}
                        }while(!message.equals("SERVER_END"));      
    }
	
	public void decryption(byte[] cipherText, String timeString)throws Exception {
		
		System.out.println("start of decryption");
		System.out.println("mesage before decrytion method in bytes" +cipherText);
		byte[] decipheredMessage = decrypt(cipherText, clientKey.getPrivate());
		
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
			if (s2-sub2 > 60){
				System.out.println("Replayed message");
			}
			else{
				System.out.println(s2-sub2);
				System.out.println("Original message");
			}
		}
		else{
			System.out.println("Replayed message");
		}
		
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
        publicSignature.initVerify(serverPublicKey);
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
		showMessage("\n"+"SERVER-"+result);
		output.flush();
		
	}

    private void closeConn() throws Exception{
        showMessage("\n Bye Bye!! ");
        ableToType(false);
        closing();
        setVisible(false);
        try{
            output.close();
            input.close();
            connection.close();
        }catch(IOException io){
            io.printStackTrace();
        }
    }
   /* static void sendData(String message) throws IOException, ClassNotFoundException{
        try{
            output.writeUTF("CLIENT - " + message);
            output.flush();
            showMessage("\nCLIENT - "+message);
        }catch(IOException io){
        	io.printStackTrace();
        }
    }*/

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
    
    public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws Exception {
		System.out.println("start of decryption method");
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] x = decriptCipher.doFinal(encrypted);
        System.out.println("end of decryption method");
        return x;
    }
    
  public static void closing() throws Exception {
	  encryption("END_USER");
  }
}
