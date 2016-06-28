package message.bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Response extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final String chainHash;
    private final Request request;
    
    public Response(String hash, Request req) {
        super(MessageType.Response);
        
        this.chainHash = hash;
        this.request = req;
        
        super.add2Body("chainhash", hash);
        super.add2Body(MessageType.Request.name(), request.toString());
    }
    
    public Response(String rStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(rStr, publicKey);
        
        this.chainHash = String.valueOf(bodyContents.get("chainhash"));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public String getChainHash() {
        return chainHash;
    }
    
    public Request getRequest() {
        return request;
    }
}
