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
    private static final long serialVersionUID = 20160629L;
    private final Integer itemId;
    private final String encryptedUserId;
    private final String encryptedPrice;
    private final Integer availableTcpPort;
    
    public Request(Integer itemId, String encUserId, String encPrice, Integer port) {
        super(MessageType.Request);
        
        this.itemId = itemId;
        this.encryptedUserId = encUserId;
        this.encryptedPrice = encPrice;
        this.availableTcpPort = port;
        
        super.add2Body("item", itemId.toString());
        super.add2Body("uid", encryptedUserId);
        super.add2Body("price", encryptedPrice);
        super.add2Body("port", availableTcpPort.toString());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.itemId = Integer.decode(String.valueOf(bodyContents.get("item")));
        this.encryptedUserId = String.valueOf(bodyContents.get("uid"));
        this.encryptedPrice = String.valueOf(bodyContents.get("price"));
        this.availableTcpPort = Integer.decode(String.valueOf(bodyContents.get("port")));
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
    
    public Integer getPort() {
        return availableTcpPort;
    }
}
