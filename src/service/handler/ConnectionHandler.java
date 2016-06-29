package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Map;

import client.Client;
import service.ConnectionType;
import service.Key;
import service.KeyManager;

/**
 *
 * @author Scott
 */
public abstract class ConnectionHandler implements Runnable {
    private static final Logger LOGGER;
    
    static {
        LOGGER = Logger.getLogger(Client.class.getName());
    }
    
    protected final ConnectionType type;
    protected final KeyPair keyPair;
    protected final Map<String, String> keyInfo;
    
    protected Socket socket;
    protected DatagramPacket datagramPacket;
    
    private ConnectionHandler(ConnectionType type, Key key) {
        KeyManager keyManager = KeyManager.getInstance();
        this.keyPair = keyManager.getKeyPair(key);
        this.keyInfo = keyManager.getKeyInfo(key);
        this.type = type;
    }
    
    public ConnectionHandler(Socket socket, Key key) {
        this(ConnectionType.TCP, key);
        
        this.socket = socket;
    }
    
    public ConnectionHandler(DatagramPacket datagram, Key key) {
        this(ConnectionType.UDP, key);
        
        this.datagramPacket = datagram;
    }
    
    protected abstract void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException;
    
    protected abstract void handle(DatagramPacket datagramPacket)
            throws SignatureException;
    
    @Override
    public void run() {
        switch (type) {
            case TCP:
                try (DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                     DataInputStream in = new DataInputStream(socket.getInputStream())) {
                    handle(out, in);

                    socket.close();
                } catch (IOException | SignatureException | IllegalAccessException ex) {
                    LOGGER.log(Level.SEVERE, null, ex);
                }
                
                break;
            case UDP:
                try {
                    handle(datagramPacket);
                } catch (SignatureException ex) {
                    LOGGER.log(Level.SEVERE, null, ex);
                }
                
                break;
        }
    }
}
