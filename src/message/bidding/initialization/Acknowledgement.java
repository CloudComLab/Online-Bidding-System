package message.bidding.initialization;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import message.JsonWebToken;
import message.MessageType;
import utility.CryptoUtils;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends JsonWebToken {
    private static final long serialVersionUID = 20160630L;
    private final KeyPair auctionKey;
    private final Map<String, String> auctionKeyInfo;
    private final Request request;
    
    public Acknowledgement(KeyPair ak, Map<String, String> akInfo, Request req) {
        super(MessageType.Acknowledgement);
        
        this.auctionKey = ak;
        this.auctionKeyInfo = akInfo;
        this.request = req;
        
        super.add2Body("ak-public", CryptoUtils.encodeKey(ak.getPublic()));
        super.add2Body("ak-private", CryptoUtils.encodeKey(ak.getPrivate()));
        super.add2Body("ak-info", akInfo);
        super.add2Body(MessageType.Request.name(), request.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        PublicKey pubKey = CryptoUtils.decodePublicKey(String.valueOf(bodyContents.get("ak-public")));
        PrivateKey priKey = CryptoUtils.decodePrivateKey(String.valueOf(bodyContents.get("ak-private")));
        
        this.auctionKey = new KeyPair(pubKey, priKey);
        this.auctionKeyInfo = (Map<String, String>) bodyContents.get("ak-info");
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public KeyPair getAuctionKey() {
        return auctionKey;
    }
    
    public Map<String, String> getAuctionKeyInfo() {
        return auctionKeyInfo;
    }
    
    public Request getRequest() {
        return request;
    }
}
