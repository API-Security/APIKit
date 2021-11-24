package burp.utils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Executor {
    // public static ExecutorService executor = Executors.newCachedThreadPool();
    public static ExecutorService executor = Executors.newFixedThreadPool(16);

    private Executor() {

    }

    public static ExecutorService getExecutor() {
        return executor;
    }
}
