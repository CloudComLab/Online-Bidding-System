package message.bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final String userId;
    private final String price;
    private final Boolean bidSuccess;
    private final ReplyResponse replyResponse;
    
    public Acknowledgement(String userId, String price, Boolean bidSuccess,
            ReplyResponse rr) {
        super(MessageType.Acknowledgement);
        
        this.userId = userId;
        this.price = price;
        this.bidSuccess = bidSuccess;
        this.replyResponse = rr;
        
        super.add2Body("user-id", userId);
        super.add2Body("price", price);
        super.add2Body("bid-success", bidSuccess.toString());
        super.add2Body(MessageType.ReplyResponse.name(), replyResponse.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.userId = String.valueOf(bodyContents.get("user-id"));
        this.price = String.valueOf(bodyContents.get("price"));
        this.bidSuccess = Boolean.valueOf(String.valueOf(bodyContents.get("bid-success")));
        this.replyResponse = new ReplyResponse(
                String.valueOf(bodyContents.get(MessageType.ReplyResponse.name())),
                null);
    }
    
    public String getUserId() {
        return userId;
    }
    
    public String getPrice() {
        return price;
    }
    
    public boolean isBidSuccess() {
        return bidSuccess;
    }
    
    public ReplyResponse getReplyResponse() {
        return replyResponse;
    }
}
