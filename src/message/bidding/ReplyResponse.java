package message.bidding;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class ReplyResponse extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final String key4UserId;
    private final String key4Price;
    private final Response response;
    
    public ReplyResponse(String k1, String k2, Response res) {
        super(MessageType.ReplyResponse);
        
        this.key4UserId = k1;
        this.key4Price = k2;
        this.response = res;
        
        super.add2Body("k1", k1);
        super.add2Body("k2", k2);
        super.add2Body(MessageType.Response.name(), response.toString());
    }
    
    public ReplyResponse(String rrStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(rrStr, publicKey);
        
        this.key4UserId = String.valueOf(bodyContents.get("k1"));
        this.key4Price = String.valueOf(bodyContents.get("k2"));
        this.response = new Response(
                String.valueOf(bodyContents.get(MessageType.Response.name())),
                (RSAPublicKey) null);
    }
    
    public String getKey4UserId() {
        return key4UserId;
    }
    
    public String getKey4Price() {
        return key4Price;
    }
    
    public Response getResponse() {
        return response;
    }
}