package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import message.BidOperation;
import message.intuitive_bidding.*;
import message.Operation;
import message.OperationType;
import service.Config;
import service.Key;
import service.handler.BiddingHandler;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class IntuitiveBidder extends Client {
    private String lastChainHash;
    
    public IntuitiveBidder(Key cliKey, Key spKey) {
        super(Config.SERVICE_HOSTNAME,
              Config.INTUITIVE_BIDDER_SERVICE_PORT,
              cliKey,
              spKey,
              true);

        this.lastChainHash = Config.INITIAL_HASH;
    }

    public String getLastChainHash() {
        return lastChainHash;
    }

    @Override
    public void execute(Operation op) {
        if (op.getType() == OperationType.AUDIT) {
            return ;
        }
        
        BidOperation bidOp = new BidOperation(op);

        final int tcpPort = Utils.findAvailableTcpPort();

        Request req = new Request(
                bidOp.getItemId(),
                bidOp.getUserId(),
                bidOp.getPrice(),
                tcpPort);

        req.sign(clientKeyPair, clientKeyInfo);
        
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            byte[] reqBytes = req.toString().getBytes();
            DatagramPacket reqPacket = new DatagramPacket(
                    reqBytes,
                    reqBytes.length,
                    InetAddress.getByName(Config.SERVICE_HOSTNAME),
                    Config.INTUITIVE_BIDDER_SERVICE_UDP_PORT);
            
            clientSocket.send(reqPacket);
        } catch (IOException ex) {
            Logger.getLogger(Bidder.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try (ServerSocket socketServer = new ServerSocket(tcpPort);
             Socket socket = socketServer.accept();
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
            
            Acknowledgement ack = new Acknowledgement(
                    Utils.receive(in),
                    (RSAPublicKey) serviceProviderKeyPair.getPublic());

            String result = "";

            if (!lastChainHash.equals(ack.getChainHash())) {
                result += "chain hash mismatch.\n";
            }

            lastChainHash = Utils.digest(req.toString());

            if (!ack.isBidSuccess()) {
                result += "bid price is lower than other's.\n";
            }

            System.out.print(result);
        } catch (IOException | SignatureException ex) {
            Logger.getLogger(Bidder.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    @Override
    protected void handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
    }
    
    @Override
    public String getHandlerAttestationPath() {
        return BiddingHandler.ATTESTATION.getPath();
    }

    @Override
    public boolean audit(File spFile) {
        return true;
    }
}
