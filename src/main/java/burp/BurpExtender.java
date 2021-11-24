package burp;

import burp.ui.ConfigPanel;
import burp.ui.ExtensionTab;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    public static String VERSION = "1.0";
    public static String NAME = "APIKit";
    public static String FULLNAME = NAME + " v" + VERSION;

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ConfigPanel configPanel;
    private static CookieManager cookieManager;
    private static ExtensionTab extensionTab;
    private static PassiveScanner passiveScanner;

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static ConfigPanel getConfigPanel() {
        return configPanel;
    }

    public static void setConfigPanel(ConfigPanel configPanel) {
        BurpExtender.configPanel = configPanel;
    }

    public static CookieManager getCookieManager() {
        return cookieManager;
    }

    public static ExtensionTab getExtensionTab() {
        return extensionTab;
    }

    public static PassiveScanner getPassiveScanner() {
        return passiveScanner;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        BurpExtender.stdout = new PrintWriter(callbacks.getStdout(), true);
        BurpExtender.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 标签界面, ExtensionTab 构造时依赖 BurpExtender.callbacks, 所以这个必须放在下面
        BurpExtender.extensionTab = new ExtensionTab(NAME);
        BurpExtender.cookieManager = new CookieManager();
        BurpExtender.passiveScanner = new PassiveScanner();

        callbacks.registerScannerCheck(passiveScanner);
        callbacks.registerHttpListener(BurpExtender.cookieManager);
        callbacks.registerContextMenuFactory(new ContextMenu());

        callbacks.setExtensionName(FULLNAME);
        BurpExtender.stdout.println("===================================");
        BurpExtender.stdout.println(String.format("%s load success!", FULLNAME));
        BurpExtender.stdout.println("Author: yulige,rmb122");
        BurpExtender.stdout.println("===================================");
    }
}