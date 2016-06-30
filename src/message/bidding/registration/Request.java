package message.bidding.registration;

import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;
import utility.CryptoUtils;

/**
 *
 * @author Scott
 */
public class Request extends JsonWebToken {
    private static final long serialVersionUID = 20160630L;
    private final String name;
    private final PublicKey publicKey;
    
    public Request(String name, PublicKey publicKey) {
        super(MessageType.Request);
        
        this.name = name;
        this.publicKey = publicKey;
        
        super.add2Body("name", name);
        super.add2Body("pk", CryptoUtils.encodeKey(publicKey));
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.name = String.valueOf(bodyContents.get("name"));
        this.publicKey = CryptoUtils.decodePublicKey(String.valueOf(bodyContents.get("pk")));
    }
    
    public String getName() {
        return name;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
}
