package message.bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Request extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final Integer itemId;
    private final String encryptedUserId;
    private final String encryptedPrice;
    
    public Request(Integer itemId, String encUserId, String encPrice) {
        super(MessageType.Request);
        
        this.itemId = itemId;
        this.encryptedUserId = encUserId;
        this.encryptedPrice = encPrice;
        
        super.add2Body("item-id", itemId.toString());
        super.add2Body("user-id", encryptedUserId);
        super.add2Body("price", encryptedPrice);
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.itemId = Integer.decode(String.valueOf(bodyContents.get("item-id")));
        this.encryptedUserId = String.valueOf(bodyContents.get("user-id"));
        this.encryptedPrice = String.valueOf(bodyContents.get("price"));
    }
    
    public Integer getItemId() {
        return itemId;
    }
    
    public String getEncryptedUserId() {
        return encryptedUserId;
    }
    
    public String getEncryptedPrice() {
        return encryptedPrice;
    }
}