package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import message.intuitive_bidding.*;
import service.Config;
import service.HashingChainTable;
import service.Key;
import service.KeyManager;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class IntuitiveBiddingHandler extends ConnectionHandler {
    public static final File ATTESTATION;
    public static final Logger LOGGER;
    
    private static final Map<Integer, Integer> PRICE_TABLE;
    private static final HashingChainTable HASHING_CHAIN_TABLE;
    private static final ReentrantLock LOCK;
    
    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/intuitive-bidding");
        LOGGER = Logger.getLogger(BiddingHandler.class.getName());
        
        PRICE_TABLE = new ConcurrentHashMap<>();
        HASHING_CHAIN_TABLE = new HashingChainTable();
        LOCK = new ReentrantLock();
    }
    
    public IntuitiveBiddingHandler(DatagramPacket datagramPacket, Key key) {
        super(datagramPacket, key);
    }
    
    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void handle(DatagramPacket datagramPacket)
            throws SignatureException {
        KeyManager keyManager = KeyManager.getInstance();
        RSAPublicKey clientPubKey = (RSAPublicKey) keyManager.getPublicKey(Key.CLIENT);
        
        byte[] reqBytes = Arrays.copyOf(datagramPacket.getData(), datagramPacket.getLength());
        Request req = new Request(new String(reqBytes), clientPubKey);
        
        String chainHash = null;
        
        LOCK.lock();
        try {
            String itemId = req.getItemId().toString();

            System.out.format("received: itemId=%2d, userId=%s, price=%s\n",
                    req.getItemId(), req.getUserId(), req.getPrice());

            chainHash = HASHING_CHAIN_TABLE.getLastChainHash(itemId);
            HASHING_CHAIN_TABLE.chain(itemId, Utils.digest(req.toString()));
        } finally {
            LOCK.unlock();
        }

        int currentPrice = PRICE_TABLE.getOrDefault(req.getItemId(), 0);
        int bidderPrice = Integer.decode(req.getPrice());
        boolean bidSuccess = bidderPrice > currentPrice;

        if (bidSuccess) {
            PRICE_TABLE.put(req.getItemId(), bidderPrice);
        }

        System.out.format("decrypted price: %d, now highest price is %d\n",
                bidderPrice, Math.max(bidderPrice, currentPrice));

        Acknowledgement ack = new Acknowledgement(chainHash, bidSuccess, req);

        ack.sign(keyPair, keyInfo);
        
        try (Socket s = new Socket(datagramPacket.getAddress(), req.getPort());
             DataOutputStream out = new DataOutputStream(s.getOutputStream());
             DataInputStream in = new DataInputStream(s.getInputStream())) {
            Utils.send(out, ack.toString());
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
}
