package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

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
    protected void handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        if (op.getType() == OperationType.AUDIT) {
            return ;
        }
        
        BidOperation bidOp = new BidOperation(op);

        Random r = new Random();
        String k1 = "k1-" + r.nextLong();
        String k2 = "k2-" + r.nextLong();

        Request req = new Request(
                bidOp.getItemId(),
                CryptoUtils.encrypt(k1, bidOp.getUserId()),
                CryptoUtils.encrypt(k2, bidOp.getPrice()));

        req.sign(clientKeyPair, clientKeyInfo);

        Utils.send(out, req.toString());

        Response res = new Response(
                Utils.receive(in),
                (RSAPublicKey) serviceProviderKeyPair.getPublic());

        String result = "";

        if (!lastChainHash.equals(res.getChainHash())) {
            result += "chain hash mismatch.\n";
        }

        lastChainHash = Utils.digest(req.toString());

        synchronized (this) {
            Utils.write(ATTESTATION, req.toString());
        }

        ReplyResponse rr = new ReplyResponse(k1, k2, res);

        rr.sign(clientKeyPair, clientKeyInfo);

        Utils.send(out, rr.toString());

        Acknowledgement ack = new Acknowledgement(
                Utils.receive(in),
                (RSAPublicKey) serviceProviderKeyPair.getPublic());

        if (!ack.isBidSuccess()) {
            result += "bid price is lower than other's.\n";
        }

        String fname = "";

        switch (op.getType()) {
            case BID:
                if (!bidOp.getUserId().equals(ack.getUserId())) {
                    result += "user id is not correctly decrypted.\n";
                }
                
                if (!bidOp.getPrice().equals(ack.getPrice())) {
                    result += "price is not correctly decrypted.\n";
                }
                
                break;
            case AUDIT:
                fname = String.format("%s/%s%s",
                            Config.DOWNLOADS_DIR_PATH,
                            op.getPath(),
                            fname);

                File file = new File(fname);

                Utils.receive(in, file);

                break;
        }
        
        System.out.print(result);
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
