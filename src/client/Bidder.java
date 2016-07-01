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
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import message.BidOperation;
import message.bidding.*;
import message.Operation;
import message.OperationType;
import service.Config;
import service.Key;
import service.handler.BiddingHandler;
import utility.CryptoUtils;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class Bidder extends Client {
    private static final File ATTESTATION;
    public static long TotalCost = -1;

    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/client/bidding");
    }

    private String lastChainHash;
    
    public Bidder(Key cliKey, Key spKey) {
        super(Config.SERVICE_HOSTNAME,
              Config.BIDDING_SERVICE_PORT,
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
        
        final int tcpPort = Utils.findAvailableTcpPort();
        
        long time = System.currentTimeMillis();
        BidOperation bidOp = new BidOperation(op);

        Random r = new Random();
        final String k1 = "k1-" + r.nextLong();
        final String k2 = "k2-" + r.nextLong();

        Request req = new Request(
                bidOp.getItemId(),
                CryptoUtils.encrypt(k1, bidOp.getUserId()),
                CryptoUtils.encrypt(k2, bidOp.getPrice()),
                tcpPort);

        req.sign(clientKeyPair, clientKeyInfo);

        try (DatagramSocket clientSocket = new DatagramSocket()) {
            byte[] reqBytes = req.toString().getBytes();
            DatagramPacket reqPacket = new DatagramPacket(
                    reqBytes,
                    reqBytes.length,
                    InetAddress.getByName(Config.SERVICE_HOSTNAME),
                    Config.BIDDING_SERVICE_UDP_PORT);
            
            clientSocket.send(reqPacket);
        } catch (IOException ex) {
            Logger.getLogger(Bidder.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try (ServerSocket socketServer = new ServerSocket(tcpPort);
             Socket socket = socketServer.accept();
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
            
            Response res = new Response(
                    Utils.receive(in),
                    (RSAPublicKey) serviceProviderKeyPair.getPublic());

            String result = "";

            if (!lastChainHash.equals(res.getChainHash())) {
                result += "chain hash mismatch.\n";
            }

            lastChainHash = Utils.digest(req.toString());

            ReplyResponse rr = new ReplyResponse(k1, k2, res);

            rr.sign(clientKeyPair, clientKeyInfo);

            Utils.send(out, rr.toString());

            Acknowledgement ack = new Acknowledgement(
                    Utils.receive(in),
                    (RSAPublicKey) serviceProviderKeyPair.getPublic());

            if (!ack.isBidSuccess()) {
                result += "bid price is lower than other's.\n";
            }

            switch (op.getType()) {
                case BID:
                    if (!bidOp.getUserId().equals(ack.getUserId())) {
                        result += "user id is not correctly decrypted.\n";
                    }

                    if (!bidOp.getPrice().equals(ack.getPrice())) {
                        result += "price is not correctly decrypted.\n";
                    }

                    break;
            }

            System.out.print(result);
        } catch (IOException | SignatureException ex) {
            Logger.getLogger(Bidder.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        if (TotalCost < 0) {
            TotalCost = 0;
        } else {
            TotalCost += System.currentTimeMillis() - time;
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
