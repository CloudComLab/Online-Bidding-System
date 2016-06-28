package message;

/**
 *
 * @author Scott
 */
public class BidOperation extends Operation {
    public BidOperation(Integer itemId, String userId, String price) {
        super(OperationType.BID,
              itemId.toString(),
              price,
              userId);
    }
    
    public BidOperation(Operation op) {
        super(op.getType(),
              op.getPath(),
              op.getMessage(),
              op.getClientID());
    }
    
    public Integer getItemId() {
        return Integer.decode(super.getPath());
    }
    
    public String getUserId() {
        return super.getClientID();
    }
    
    public String getPrice() {
        return super.getMessage();
    }
}
