package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import message.bidding.*;
import service.Config;
import service.HashingChainTable;
import service.Key;
import service.KeyManager;
import utility.CryptoUtils;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class BiddingHandler extends ConnectionHandler {
    public static final File ATTESTATION;
    
    private static final Map<Integer, Integer> PRICE_TABLE;
    private static final HashingChainTable HASHING_CHAIN_TABLE;
    private static final ReentrantLock LOCK;
    
    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/bidding");
        
        PRICE_TABLE = new ConcurrentHashMap<>();
        HASHING_CHAIN_TABLE = new HashingChainTable();
        LOCK = new ReentrantLock();
    }
    
    public BiddingHandler(Socket socket, Key key) {
        super(socket, key);
    }
    
    // https://systembash.com/a-simple-java-udp-server-and-udp-client/
    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        KeyManager keyManager = KeyManager.getInstance();
        RSAPublicKey clientPubKey = (RSAPublicKey) keyManager.getPublicKey(Key.CLIENT);
        Lock lock = null;
        
        try {
            Request req = new Request(Utils.receive(in), clientPubKey);
            
            LOCK.lock();
            try {
                String itemId = req.getItemId().toString();
                
                System.out.format("received: itemId=%2d, userId=%s, price=%s\n",
                        req.getItemId(), req.getEncryptedUserId(), req.getEncryptedPrice());

                String lastChainHash = HASHING_CHAIN_TABLE.getLastChainHash(itemId);

                Response res = new Response(lastChainHash, req);

                res.sign(keyPair, keyInfo);

                Utils.send(out, res.toString());

                HASHING_CHAIN_TABLE.chain(itemId, Utils.digest(req.toString()));
//                Utils.appendAndDigest(ATTESTATION, req.toString() + '\n');
            } finally {
                LOCK.unlock();
            }

            ReplyResponse rr = new ReplyResponse(Utils.receive(in), clientPubKey);

            String userId = CryptoUtils.decrypt(rr.getKey4UserId(), req.getEncryptedUserId());
            String price = CryptoUtils.decrypt(rr.getKey4Price(), req.getEncryptedPrice());
            
            int currentPrice = PRICE_TABLE.getOrDefault(req.getItemId(), 0);
            int bidderPrice = Integer.decode(price);
            boolean bidSuccess = bidderPrice > currentPrice;
            
            if (bidSuccess) {
                PRICE_TABLE.put(req.getItemId(), bidderPrice);
            }
            
            System.out.format("decrypted price: %d, now highest price is %d\n",
                    bidderPrice, Math.max(bidderPrice, currentPrice));
            
            Acknowledgement ack = new Acknowledgement(userId, price, bidSuccess, rr);
            
            ack.sign(keyPair, keyInfo);
            
            String ackStr = ack.toString();
            
            Utils.send(out, ackStr);
        } finally {
            if (lock != null) {
                lock.unlock();
            }
        }
    }
}
