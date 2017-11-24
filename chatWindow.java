import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.SpringLayout;


public class chatWindow extends JFrame {

	private JPanel contentPane;
	private static JTextField textField;
	private static JTextArea txtrClientMessages;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					chatWindow frame = new chatWindow();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 * @throws InvocationTargetException 
	 * @throws InterruptedException 
	 */
	public chatWindow() throws IOException, ClassNotFoundException, InterruptedException, InvocationTargetException {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(500, 500, 500, 500);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		SpringLayout sl_contentPane = new SpringLayout();
		contentPane.setLayout(sl_contentPane);
		
		setTitle("Client Chat Window");
		
		txtrClientMessages = new JTextArea();
		sl_contentPane.putConstraint(SpringLayout.WEST, txtrClientMessages, -5, SpringLayout.WEST, contentPane);
		sl_contentPane.putConstraint(SpringLayout.EAST, txtrClientMessages, -74, SpringLayout.EAST, contentPane);
		txtrClientMessages.setTabSize(0);
		sl_contentPane.putConstraint(SpringLayout.NORTH, txtrClientMessages, 6, SpringLayout.SOUTH, contentPane);
		contentPane.add(txtrClientMessages);
		
		
		txtrClientMessages.setLineWrap(true);
		txtrClientMessages.setEditable(false);
		
		 JScrollPane scroll = new JScrollPane (txtrClientMessages);
		 sl_contentPane.putConstraint(SpringLayout.NORTH, scroll, 67, SpringLayout.NORTH, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.WEST, scroll, 29, SpringLayout.WEST, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.SOUTH, scroll, 434, SpringLayout.NORTH, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.EAST, scroll, -21, SpringLayout.EAST, contentPane);
		 scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		 contentPane.add(scroll);
		 
		 textField = new JTextField();
		 sl_contentPane.putConstraint(SpringLayout.NORTH, textField, 10, SpringLayout.NORTH, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.WEST, textField, 29, SpringLayout.WEST, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.SOUTH, textField, -9, SpringLayout.NORTH, scroll);
		 sl_contentPane.putConstraint(SpringLayout.EAST, textField, -21, SpringLayout.EAST, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.WEST, txtrClientMessages, -5, SpringLayout.WEST, contentPane);
		 sl_contentPane.putConstraint(SpringLayout.EAST, txtrClientMessages, -74, SpringLayout.EAST, contentPane);

		 contentPane.add(textField);
		 //Client.setupStreams();
		 textField.addActionListener(
	                new ActionListener(){
	                    @Override
	                    public void actionPerformed(ActionEvent e) {
	                        //Client.sendData(textField.getText());
	                        textField.setText("");
	                    }
	                }
	        );
		 
		 textField.setColumns(10);
	}

    static void showMessage(final String text){
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                        //chatWindow.append(text);
                    	txtrClientMessages.append(text);
                    	System.out.println(text);
                    }

                }
        );
    }

    static void ableToType(final boolean tof){
        SwingUtilities.invokeLater(
                new Runnable(){
                    public void run(){
                       // userText.setEditable(tof);
                    	textField.setEditable(tof);
                        System.out.println("Able to type"+tof);
                    }

                }
        );
    }
}
