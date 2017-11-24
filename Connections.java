import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JOptionPane;
import javax.swing.SpringLayout;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;


public class Connections extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8474152136100287391L;
	private JPanel contentPane;
	private JTextField textField;
	private JButton btnConnect;

	/**
	 * Launch the application.
	 */
	public static void main() {
		
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Connections frame = new Connections();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	/**
	 * Create the frame.
	 * @throws SQLException 
	 */
	public Connections(){
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		SpringLayout sl_contentPane = new SpringLayout();
		contentPane.setLayout(sl_contentPane);
		
		JLabel lblUsername = new JLabel("Username:");
		sl_contentPane.putConstraint(SpringLayout.NORTH, lblUsername, 31, SpringLayout.NORTH, contentPane);
		sl_contentPane.putConstraint(SpringLayout.WEST, lblUsername, 31, SpringLayout.WEST, contentPane);
		contentPane.add(lblUsername);
		
		textField = new JTextField();
		sl_contentPane.putConstraint(SpringLayout.WEST, textField, 47, SpringLayout.EAST, lblUsername);
		sl_contentPane.putConstraint(SpringLayout.SOUTH, textField, 0, SpringLayout.SOUTH, lblUsername);
		contentPane.add(textField);
		textField.setColumns(10);
		
		btnConnect = new JButton("Connect");
		sl_contentPane.putConstraint(SpringLayout.NORTH, btnConnect, 50, SpringLayout.NORTH, contentPane);
		sl_contentPane.putConstraint(SpringLayout.EAST, btnConnect, -33, SpringLayout.EAST, contentPane);
		contentPane.add(btnConnect);
		
		btnConnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent a) {

				String username = "";

				username = textField.getText().trim();
				
				if (username.equals("")){
					JOptionPane.showMessageDialog(null," Please enter valid username to connect!","Error",JOptionPane.ERROR_MESSAGE);
				}
				else {
					try {
						Client.connectionCheck(username);
						//setVisible(false);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					}
				}
			//}
		});
		setTitle("Connections");
	}
	
}
