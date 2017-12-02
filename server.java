import java.io.IOException;

class server {
    public static void main(String[] args) throws IOException {
        ServerThread sally = new ServerThread(80, 100);
        sally.run();
        //Handler hand = new Handler(5000);
        //hand.run();
    }
}
