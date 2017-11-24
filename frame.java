import java.awt.EventQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.SpringLayout;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JPasswordField;

import com.jgoodies.forms.factories.DefaultComponentFactory;


public class frame extends JFrame {


	private JPanel contentPane;
	private JTextField textField;
	private JPasswordField passwordField;
	
	String username = "";
	String password = "";
	private JTextField textField_1;
	private JPasswordField passwordField_1;


	/**
	 * Launch the application.
	 */
	public static void main(String[] args){
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					frame frame = new frame();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	/**
	 * Create the frame.
	 * @return 
	 */
	public frame() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(500, 100, 450, 500);
		SpringLayout springLayout_1 = new SpringLayout();
		getContentPane().setLayout(springLayout_1);
		
		JLabel lblTextme = DefaultComponentFactory.getInstance().createTitle("TextME");
		springLayout_1.putConstraint(SpringLayout.NORTH, lblTextme, 10, SpringLayout.NORTH, getContentPane());
		springLayout_1.putConstraint(SpringLayout.WEST, lblTextme, 195, SpringLayout.WEST, getContentPane());
		getContentPane().add(lblTextme);
		
		JLabel lblNewLabel = new JLabel("New label");
		springLayout_1.putConstraint(SpringLayout.NORTH, lblNewLabel, 6, SpringLayout.SOUTH, lblTextme);
		springLayout_1.putConstraint(SpringLayout.WEST, lblNewLabel, 83, SpringLayout.WEST, getContentPane());
		springLayout_1.putConstraint(SpringLayout.EAST, lblNewLabel, -64, SpringLayout.EAST, getContentPane());
		getContentPane().add(lblNewLabel);
		lblNewLabel.setIcon(new ImageIcon("/Users/PranathiVasireddy/Desktop/unnamed.png"));
		
		JLabel lblUsername = new JLabel("Username:");
		getContentPane().add(lblUsername);
		
		JLabel lblPassword = new JLabel("Password:");
		springLayout_1.putConstraint(SpringLayout.WEST, lblPassword, 61, SpringLayout.WEST, getContentPane());
		springLayout_1.putConstraint(SpringLayout.SOUTH, lblPassword, -39, SpringLayout.SOUTH, getContentPane());
		springLayout_1.putConstraint(SpringLayout.EAST, lblUsername, 0, SpringLayout.EAST, lblPassword);
		getContentPane().add(lblPassword);
		
		textField_1 = new JTextField();
		springLayout_1.putConstraint(SpringLayout.WEST, textField_1, 20, SpringLayout.EAST, lblUsername);
		springLayout_1.putConstraint(SpringLayout.NORTH, lblUsername, 6, SpringLayout.NORTH, textField_1);
		getContentPane().add(textField_1);
		textField_1.setColumns(10);

		
		passwordField_1 = new JPasswordField();
		springLayout_1.putConstraint(SpringLayout.WEST, passwordField_1, 25, SpringLayout.EAST, lblPassword);
		springLayout_1.putConstraint(SpringLayout.SOUTH, passwordField_1, -31, SpringLayout.SOUTH, getContentPane());
		springLayout_1.putConstraint(SpringLayout.EAST, passwordField_1, 0, SpringLayout.EAST, textField_1);
		getContentPane().add(passwordField_1);
		
		JButton btnNewUser = new JButton("Sign Up");
		springLayout_1.putConstraint(SpringLayout.NORTH, textField_1, -1, SpringLayout.NORTH, btnNewUser);
		springLayout_1.putConstraint(SpringLayout.EAST, btnNewUser, -22, SpringLayout.EAST, getContentPane());
		getContentPane().add(btnNewUser);
		btnNewUser.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent a) {
				String username = "";
				String password = "";
				username = textField_1.getText().trim();
				password = String.valueOf(passwordField_1.getPassword());
				if (username.equals("") || password.equals(""))
				{
					JOptionPane.showMessageDialog(null," Please enter valid credentials!","Error",JOptionPane.ERROR_MESSAGE);
				}
				else {	
					System.out.println(username);
					System.out.println(password);
					try {
						Client.infoExchange(username, password,"Sign Up");
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (ClassNotFoundException e) {
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
					}
				}
			}
		});
		
		JButton btnSignIn = new JButton("Sign In");
		springLayout_1.putConstraint(SpringLayout.SOUTH, btnNewUser, -32, SpringLayout.NORTH, btnSignIn);
		springLayout_1.putConstraint(SpringLayout.NORTH, btnSignIn, -5, SpringLayout.NORTH, lblPassword);
		springLayout_1.putConstraint(SpringLayout.EAST, btnSignIn, 0, SpringLayout.EAST, btnNewUser);
		getContentPane().add(btnSignIn);
		btnSignIn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent a) {
				String username = "";
				String password = "";

				username = textField_1.getText().trim();
				password = String.valueOf(passwordField_1.getPassword());
				
				if (username.equals("") || password.equals(""))
				{
					JOptionPane.showMessageDialog(null," Please enter valid credentials!","Error",JOptionPane.ERROR_MESSAGE);
				}
				else {	
					System.out.println(username);
					System.out.println(password);
					try {
						Client.infoExchange(username, password, "Sign In");
						setVisible(false);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (ClassNotFoundException e) {
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
					}
				}
			}
		});
		contentPane = new JPanel();
		SpringLayout springLayout = new SpringLayout();
		contentPane.setLayout(springLayout);
	}
}