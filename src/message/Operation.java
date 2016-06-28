package message;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author Scott
 */
public class Operation {
    private final OperationType type;
    private final String path;
    private final String message;
    private final String clientId;
    private final LinkedHashMap<String, String> map;
    
    public Operation(OperationType type, String path, String msg) {
        this(type, path, msg, "");
    }
    
    public Operation(OperationType type, String path, String msg, String clientId) {
        this.type = type;
        this.path = path.indexOf('\\') != -1 ? path.replace('\\', '/') : path;
        this.message = msg;
        this.clientId = clientId;
        
        map = new LinkedHashMap<>();
        map.put("type", type.toString());
        map.put("path", path);
        map.put("message", msg);
        map.put("client-id", clientId);
    }
    
    public Operation(Map map) {
        this(OperationType.valueOf(String.valueOf(map.get("type"))),
             String.valueOf(map.get("path")),
             String.valueOf(map.get("message")),
             String.valueOf(map.get("client-id")));
    }
    
    public OperationType getType() {
        return type;
    }
    
    public String getPath() {
        return path;
    }
    
    public String getMessage() {
        return message;
    }
    
    public String getClientID() {
        return clientId;
    }
    
    public LinkedHashMap<String, String> toMap() {
        return map;
    }
}
