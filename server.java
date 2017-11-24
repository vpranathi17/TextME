import java.io.IOException;

class server {
    public static void main(String[] args) throws IOException {
        ServerThread sally = new ServerThread(5000, 100);
        sally.run();
    }
}
