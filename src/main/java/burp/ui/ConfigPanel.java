package burp.ui;

import javax.swing.*;

public class ConfigPanel extends JToolBar {
    JCheckBox autoSendRequestCheckBox;
    JCheckBox includeCookieCheckBox;

    public ConfigPanel() {
        this.autoSendRequestCheckBox = new JCheckBox("Auto request sending");
        this.includeCookieCheckBox = new JCheckBox("Send with cookie");

        // 默认不发送
        this.autoSendRequestCheckBox.setSelected(false);
        this.includeCookieCheckBox.setSelected(false);

        // 不可悬浮
        this.setFloatable(false);
        this.add(autoSendRequestCheckBox);
        this.add(includeCookieCheckBox);
    }

    public Boolean getAutoSendRequest() {
        return this.autoSendRequestCheckBox.isSelected();
    }

    public Boolean getIncludeCookie() {
        return this.includeCookieCheckBox.isSelected();
    }
}
