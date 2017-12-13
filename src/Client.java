import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Date;
import java.util.concurrent.TimeUnit;

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
    String[] userDetailsTokens;
    private static ServerSocket ssocket;
    static PublicKey key;

    String[] info;


    //constructor
    public Client(String host) throws ClassNotFoundException, InvocationTargetException, InterruptedException{
        serverIP = host;
        setTitle("Client Window");
        serverIP = host;
        userText = new JTextField();
        userText.setFont(new Font("courier", Font.PLAIN, 25));
        userText.setEditable(false);
        userText.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e) {
                        try {
                            String message = e.getActionCommand();
                            showMessage("\n"+username+"-"+message);
                            encrypt(message);
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
        ableToType(true);
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
            signinFrame();
        }
        else{
            if(reply == 0){
                signupFrame();
            }
            else{
                JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "TextME",JOptionPane.INFORMATION_MESSAGE,img);
            }
        }
    }

    private void signinFrame() throws Exception {
        ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
        JTextField Username = new JTextField(5);
        JPasswordField Password = new JPasswordField(5);

        JPanel myPanel = new JPanel();
        myPanel.setName("Sign IN");
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

    private void signupFrame() throws Exception {
        ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png");
        JTextField Username = new JTextField(5);
        JPasswordField Password = new JPasswordField(5);
        JTextField Emailid = new JTextField(20);

        JPanel myPanel = new JPanel();
        myPanel.setName("Sign UP");
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
            if (email.matches("\\[")){
                ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
                JOptionPane.showMessageDialog(null,"Please enter valid credentials!","TextME",JOptionPane.ERROR_MESSAGE,img1);
                signupFrame();
            }
            username = Username.getText();
            if (username.matches("\\[")){
                ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
                JOptionPane.showMessageDialog(null,"Please enter valid credentials!","TextME",JOptionPane.ERROR_MESSAGE,img1);
                signupFrame();
            }
            password = String.valueOf(Password.getPassword());
            if (password.matches(".*([A-Z]*.*[0-9]*.*[_.#@$%^&*!]*.)") && password.length()>=8){
                connectServer();
                infoExchange(username,password,email,"Sign Up");
            }
            else{
                ImageIcon img1 = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
                JOptionPane.showMessageDialog(null," Please choose a strong password!","TextME",JOptionPane.ERROR_MESSAGE,img1);
                signupFrame();
            }
        }
        else{
            JOptionPane.showMessageDialog(null, "See you later!! Bye!!", "TextME",JOptionPane.INFORMATION_MESSAGE,img);
        }
    }

    private void connectServer() throws IOException {
        connection = new Socket(InetAddress.getByName(serverIP), 5000);
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

//        System.out.println("Sent details are...");
//		  System.out.println(cipherText);
//        System.out.println(cipherText1);
//        System.out.println(cipherText2);
//        System.out.println(cipherText3);
//        System.out.println(clientKey.getPublic());

        dos1.flush();
        dos2.flush();
        oos.flush();
        databaseCheck();
    }

    private void databaseCheck() throws Exception{
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        String rmsg = dis.readUTF();
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
                        signinFrame();
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
                "Connections", JOptionPane.DEFAULT_OPTION, JOptionPane.OK_CANCEL_OPTION,icon);
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
        dos.flush();
        //System.out.println(cipherText);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        String statusCode = getInfofromServer(dis,dos);

        String rmsg = dis.readUTF();
        //System.out.println("--"+rmsg);
        if (rmsg.equals("connected") && statusCode.equals("1")){
            ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
            key = (PublicKey) ois.readObject();
            System.out.println(key);
            ois.close();
            connection.close();
            TimeUnit.SECONDS.sleep(2);
            if(beginChat(userDetailsTokens[4], userDetailsTokens[2]).equals("1")){
                // output.writeUTF("1");
                //output.flush();
                ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/sign-check-icon.png");
                JOptionPane.showMessageDialog(null," Connected!","TextME",JOptionPane.INFORMATION_MESSAGE,img);
                //setupStreams();
                whileChatting(userDetailsTokens[0]);
            }
            else {
                output.writeUTF("0");
                output.flush();
                ImageIcon img = new ImageIcon("/Users/PranathiVasireddy/Desktop/red_cross_x_clip_art_7568.jpg");
                JOptionPane.showMessageDialog(null," Authentication Failed!","TextME",JOptionPane.INFORMATION_MESSAGE,img);
            }

        }
        else if (rmsg.equals("connected") && statusCode.equals("0")){// enter listening phase
            int port = connection.getLocalPort();
            String token="";
            connection.close();
            System.out.println("waiting!!!!");
            System.out.println(port);


            ssocket = new ServerSocket(port);
            //System.out.println(ssocket.getLocalPort());
            connection = ssocket.accept();
            String clientInfo;
            setupStreams();
            System.out.println("120");
            while(true){
                if(input.available()> 0){
                    clientInfo = input.readUTF();
                    ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
                    key = (PublicKey) ois.readObject();
                    System.out.println(key);
                    ois.close();
                    break;
                }
            }
            output.close();
            input.close();
            System.out.println("out of the loop::"+clientInfo);
            String recvdetails[] = processConnectionInfo(clientInfo);

            connection = ssocket.accept();
            setupStreams();
            while(true){
                if(input.available()> 0){
                    token = input.readUTF();
                    System.out.println(token);
                    output.writeUTF(recvdetails[1]);
                    output.flush();
                    break;
                }
            }

            String ack = input.readUTF(); // acknowledgement for token verification

            if (recvdetails[1].equals(token) && ack.equals("1")){
                output.writeUTF("1");// success, tokens match
                System.out.println(token);
                ableToType(true);
                whileChatting(recvdetails[0]);
            }
            else{
                output.writeUTF("0"); // Failed, tokens don't match
            }

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
                //connections();
            }
        }
    }

    public void setupStreams()throws Exception{
        input = new DataInputStream(connection.getInputStream());
        output = new DataOutputStream(connection.getOutputStream());
        output.flush();
 //       System.out.println("In show up streams");
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
        System.out.println("encrypted"+encrypted);
        System.out.println("encrypted.length"+encrypted.length);
        output.writeInt(encrypted.length);
        output.write(encrypted);
        output.flush();

        System.out.println("signature"+signature);
        System.out.println("length" +signature.length);
        output.writeInt(signature.length);
        output.write(signature);
        output.flush();

 //       System.out.println("here");       
    }

    public static void encrypt(String plainText) throws Exception {

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
        encCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = encCipher.doFinal((plainText+y+timeString).getBytes());
        System.out.println("encrypted"+encrypted);
        System.out.println("encrypted.length"+encrypted.length);
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
    }

    public void whileChatting(String user)throws Exception{
        // during the chat conversation
        setVisible(true);
        //System.out.println(user);
        showMessage("Chat setup for.... "+ username);
        do{
            try {
                int length = input.readInt();
                System.out.println(length);
                byte[] cipherText = null;
                if(length>0) {
                    cipherText = new byte[length];
                    input.readFully(cipherText, 0, cipherText.length); // read the message
                }
                System.out.println(cipherText);
                String timeString = Long.toString(new Date().getTime());
                System.out.println(timeString);
                decryption(cipherText, timeString,user);
                System.out.println(message);
                showMessage(message);
            } catch (IOException e ){
                // e.printStackTrace();
                closeConn();
            }
        }while(!message.equals("SERVER_END"));
    }

    public void decryption(byte[] cipherText, String timeString, String user)throws Exception {

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

        System.out.println("result...."+result);
        System.out.println("sign...."+sign);

        int length1 = input.readInt();
        byte[] signature = null;
        if(length1>0) {
            signature = new byte[length1];
            input.readFully(signature, 0, signature.length); // read the message
        }


        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(key);
        publicSignature.update(result.getBytes());


        boolean check = publicSignature.verify(signature);
        System.out.println("check"+check);

        System.out.println("here");

        showMessage("\n"+user +"-"+result);
        output.flush();

    }


    private void closeConn() throws Exception{
        showMessage("\n Bye Bye!! ");
        ableToType(false);
        setVisible(false);
        try{
            output.close();
            input.close();
            connection.close();
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

    public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws Exception {
        System.out.println("start of decryption method");
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] x = decriptCipher.doFinal(encrypted);
        System.out.println("end of decryption method");
        return x;
    }
    private String[] processConnectionInfo(String connectionString){

        String delims = "[;]";
        String[] tokens = connectionString.split(delims);
        return tokens;
    }

    private String getInfofromServer(DataInputStream dis, DataOutputStream dos ) throws IOException {
        String rmsg = null;
        String userMsg = dis.readUTF();//get the user information to connect to the other user.
        System.out.println(userMsg);
        System.out.println("Yehah");
        if (userMsg.isEmpty()){
            dos.writeUTF("0");
            rmsg = dis.readUTF();
            // Print message on screen that "something went wrong"
            System.out.println("something went wrong :(");

        }
        else{
            dos.writeUTF("1");
            rmsg = dis.readUTF();
            System.out.println("rmsg"+rmsg);
            if (rmsg.equals("1")){// received info of the other client
                // close all connections
                //connection.close();
                userDetailsTokens = processConnectionInfo(userMsg);// 0 - username to connect, 1 - shared OTP , 2 - port , 3 - public key, 4 - IP, 5 - timestamp

                if (!(userDetailsTokens[3].isEmpty() || userDetailsTokens[5].isEmpty())){
                    //create a new socket
                    // connectToClient(userDetailsTokens[4],userDetailsTokens[2]);
                }
                //rmsg = "1";
            }
        }
        return rmsg;
    }

    private String beginChat(String host, String port) throws Exception {
        System.out.println(port);
        connection = new Socket(InetAddress.getByName(host.substring(1)), Integer.parseInt(port));
        setupStreams();
        System.out.println("120");
        // connect to the other user
        output.writeUTF(userDetailsTokens[1]);

        String token = input.readUTF();
        if (userDetailsTokens[1].equals(token)){
            output.writeUTF("1");// success, tokens match
            System.out.println(token);
        }
        else{
            output.writeUTF("0"); // Failed, tokens don't match
        }

        output.flush();

        return input.readUTF();

    }



}
