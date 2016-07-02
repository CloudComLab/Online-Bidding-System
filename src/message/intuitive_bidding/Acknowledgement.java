package message.intuitive_bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends JsonWebToken {
    private static final long serialVersionUID = 20160702L;
    private final String chainHash;
    private final Boolean bidSuccess;
    private final Request request;
    
    public Acknowledgement(String chainHash, Boolean bidSuccess,
            Request req) {
        super(MessageType.Acknowledgement);
        
        this.chainHash = chainHash;
        this.bidSuccess = bidSuccess;
        this.request = req;
        
        super.add2Body("chainhash", chainHash);
        super.add2Body("bid-success", bidSuccess.toString());
        super.add2Body(MessageType.Request.name(), request.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.chainHash = String.valueOf(bodyContents.get("chainhash"));
        this.bidSuccess = Boolean.valueOf(String.valueOf(bodyContents.get("bid-success")));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public String getChainHash() {
        return chainHash;
    }
    
    public boolean isBidSuccess() {
        return bidSuccess;
    }
    
    public Request getRequest() {
        return request;
    }
}
