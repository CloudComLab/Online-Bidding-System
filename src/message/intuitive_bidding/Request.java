package message.intuitive_bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Request extends JsonWebToken {
    private static final long serialVersionUID = 20160702L;
    private final Integer itemId;
    private final String userId;
    private final String price;
    private final Integer availableTcpPort;
    
    public Request(Integer itemId, String userId, String price, Integer port) {
        super(MessageType.Request);
        
        this.itemId = itemId;
        this.userId = userId;
        this.price = price;
        this.availableTcpPort = port;
        
        super.add2Body("item", itemId.toString());
        super.add2Body("uid", userId);
        super.add2Body("price", price);
        super.add2Body("port", availableTcpPort.toString());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.itemId = Integer.decode(String.valueOf(bodyContents.get("item")));
        this.userId = String.valueOf(bodyContents.get("uid"));
        this.price = String.valueOf(bodyContents.get("price"));
        this.availableTcpPort = Integer.decode(String.valueOf(bodyContents.get("port")));
    }
    
    public Integer getItemId() {
        return itemId;
    }
    
    public String getUserId() {
        return userId;
    }
    
    public String getPrice() {
        return price;
    }
    
    public Integer getPort() {
        return availableTcpPort;
    }
}
