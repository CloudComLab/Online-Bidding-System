package message.bidding.registration;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends JsonWebToken {
    private static final long serialVersionUID = 20160630L;
    private final Boolean regSuccess;
    private final Request request;
    
    public Acknowledgement(Boolean regSuccess, Request req) {
        super(MessageType.Acknowledgement);
        
        this.regSuccess = regSuccess;
        this.request = req;
        
        super.add2Body("reg-success", regSuccess.toString());
        super.add2Body(MessageType.Request.name(), request.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.regSuccess = Boolean.valueOf(String.valueOf(bodyContents.get("reg-success")));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public boolean isRegSuccess() {
        return regSuccess;
    }
    
    public Request getRequest() {
        return request;
    }
}
