package service;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import service.handler.ConnectionHandler;
import service.handler.NonCAPHandler;
import service.handler.BiddingHandler;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class SocketServer extends Thread {
    private int port;
    private ConnectionType type;
    private ExecutorService pool;
    private Constructor handlerCtor;
    
    public SocketServer(ConnectionType type,
                        Class<? extends ConnectionHandler> handler,
                        int port) {
        this.port = port;
        this.type = type;
        this.pool = Executors.newFixedThreadPool(Config.NUM_PROCESSORS);
        
        try {
            this.handlerCtor = handler.getDeclaredConstructor(
                    type == ConnectionType.TCP ? Socket.class : DatagramPacket.class,
                    Key.class);
        } catch (NoSuchMethodException | SecurityException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void listen4TCP() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            do {
                Socket socket = serverSocket.accept();
                
                pool.execute((Runnable) handlerCtor.newInstance(socket, Key.SERVICE_PROVIDER));
            } while (true);
        } catch (IOException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvocationTargetException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void listen4UDP() {
        try (DatagramSocket serverSocket = new DatagramSocket(port)) {
            byte[] buf = new byte[8192];
            
            do {
                DatagramPacket datagram = new DatagramPacket(buf, buf.length);
                
                serverSocket.receive(datagram);
                
                pool.execute((Runnable) handlerCtor.newInstance(datagram, Key.SERVICE_PROVIDER));
            } while (true);
        } catch (SocketException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvocationTargetException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    @Override
    public void run() {
        try {
            switch (type) {
                case TCP:
                    listen4TCP();
                    
                    break;
                case UDP:
                    listen4UDP();
                    
                    break;
            }
        } finally {
            pool.shutdown();
        }
    }
    
    public static void main(String[] args) {
        Utils.createRequiredFiles();
        Utils.cleanAllAttestations();
        
        // manually initialize jose4j
        org.jose4j.jwa.AlgorithmFactoryFactory.getInstance();
        
        new SocketServer(ConnectionType.TCP,
                         NonCAPHandler.class,
                         Config.NONCAP_SERVICE_PORT).start();
        new SocketServer(ConnectionType.UDP,
                         BiddingHandler.class,
                         Config.BIDDING_SERVICE_UDP_PORT).start();
        
        System.out.println("Ready to go!");
    }
}
