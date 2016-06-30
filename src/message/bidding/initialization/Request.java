package message.bidding.initialization;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Request extends JsonWebToken {
    private static final long serialVersionUID = 20160630L;
    private final Integer auctionId;
    
    public Request(Integer aucId) {
        super(MessageType.Request);
        
        this.auctionId = aucId;
        
        super.add2Body("auction-id", auctionId.toString());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.auctionId = Integer.decode(String.valueOf(bodyContents.get("auction-id")));
    }
    
    public Integer getAuctionId() {
        return auctionId;
    }
}
