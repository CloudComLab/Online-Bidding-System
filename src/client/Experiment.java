package client;

import java.util.ArrayList;
import java.util.List;

import message.BidOperation;
import message.Operation;
import service.Key;
import service.KeyManager;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class Experiment {
    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        
        Utils.cleanAllAttestations();
        
        // manually initialize jose4j
        org.jose4j.jwa.AlgorithmFactoryFactory.getInstance();
        
        KeyManager keyManager = KeyManager.getInstance();
        
        message.bidding.registration.Request regQ = new message.bidding.registration.Request("scott", keyManager.getPublicKey(Key.CLIENT));
        regQ.sign(keyManager.getKeyPair(Key.CLIENT), keyManager.getKeyInfo(Key.CLIENT));
        System.out.println("RegQ: " + regQ.toString().length());
        
        message.bidding.registration.Acknowledgement regAck = new message.bidding.registration.Acknowledgement(Boolean.TRUE, regQ);
        regAck.sign(keyManager.getKeyPair(Key.SERVICE_PROVIDER), keyManager.getKeyInfo(Key.SERVICE_PROVIDER));
        System.out.println("RegAck: " + regAck.toString().length());
        
        message.bidding.initialization.Request keyQ = new message.bidding.initialization.Request(3);
        keyQ.sign(keyManager.getKeyPair(Key.CLIENT), keyManager.getKeyInfo(Key.CLIENT));
        System.out.println("KeyQ: " + keyQ.toString().length());
        
        message.bidding.initialization.Acknowledgement keyAck = new message.bidding.initialization.Acknowledgement(keyManager.getKeyPair(Key.SERVICE_PROVIDER), keyManager.getKeyInfo(Key.SERVICE_PROVIDER), keyQ);
        keyAck.sign(keyManager.getKeyPair(Key.SERVICE_PROVIDER), keyManager.getKeyInfo(Key.SERVICE_PROVIDER));
        System.out.println("KeyAck: " + keyAck.toString().length());
        
        IntuitiveBidder iBidder = new IntuitiveBidder(Key.CLIENT, Key.SERVICE_PROVIDER);
        Bidder bidder = new Bidder(Key.CLIENT, Key.SERVICE_PROVIDER);
        
        int bidTimes = 1;
        
        List<Operation> ops = new ArrayList<>();
        
        for (int i = 0; i < bidTimes; i++) {
            ops.add(new BidOperation(10, "bidder", "" + (100 * (i + 1))));
        }
        
        classLoader.loadClass(IntuitiveBidder.class.getName());
        classLoader.loadClass(Bidder.class.getName());
        
        iBidder.run(ops, bidTimes);
        bidder.run(ops, bidTimes);
        
        System.out.println(Bidder.TotalCost / (bidTimes - 1));
    }
}
