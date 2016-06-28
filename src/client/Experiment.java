package client;

import java.util.ArrayList;
import java.util.List;

import message.BidOperation;
import message.Operation;
import service.Key;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class Experiment {
    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        
        Utils.cleanAllAttestations();
        
        Bidder bidder = new Bidder(Key.CLIENT, Key.SERVICE_PROVIDER);
        
        int bidTimes = 3;
        
        List<Operation> ops = new ArrayList<>();
        
        for (int i = 0; i < bidTimes; i++) {
            ops.add(new BidOperation(10, "bidder", "" + (100 * (i + 1))));
        }
        
        classLoader.loadClass(Bidder.class.getName());
        
        bidder.run(ops, bidTimes);
    }
}
