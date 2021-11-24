package burp.utils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UrlScanCount {

    private final ConcurrentHashMap<String, Integer> countMap;

    public UrlScanCount() {
        this.countMap = new ConcurrentHashMap<>();
    }

    public Map<String, Integer> getStringMap() {
        return this.countMap;
    }

    public Integer get(String key) {
        Integer ret = this.countMap.get(key);
        if (ret == null) {
            return 0;
        } else {
            return ret;
        }
    }

    public void add(String key) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("Key 不能为空");
        }

        synchronized (this.getStringMap()) {
            this.countMap.put(key, (this.get(key) + 1));
        }
    }

    public void del(String key) {
        if (this.countMap.get(key) != null) {
            this.countMap.remove(key);
        }
    }
}
