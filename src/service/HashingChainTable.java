package service;

import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author Scott
 */
public class HashingChainTable {
    private final ConcurrentHashMap<String, LinkedList<String>> table;
    
    public HashingChainTable() {
        table = new ConcurrentHashMap<>();
    }
    
    private LinkedList<String> getListOrAdd(String id) {
        LinkedList<String> list;
        
        if (table.containsKey(id)) {
            list = table.get(id);
        } else {
            list = new LinkedList<>();
            
            list.add(Config.INITIAL_HASH);
            
            table.put(id, list);
        }
        
        return list;
    }
    
    public String getLastChainHash(String id) {
        return getListOrAdd(id).getLast();
    }
    
    public void chain(String id, String hash) {
        getListOrAdd(id).addLast(hash);
    }
}
