package burp.ui;

import burp.*;
import burp.utils.Constants;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ExtensionTab extends AbstractTableModel implements ITab, IMessageEditorController {
    private final String tagName;
    private JSplitPane mainSplitPane;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private JScrollPane upScrollPane;
    private JSplitPane downSplitPane;
    private JTabbedPane requestPanel;
    private JTabbedPane responsePanel;
    private JSplitPane upSplitPane;
    private ConfigPanel configPanel;

    private ApiTable apiTable;

    public ExtensionTab(String name) {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        this.tagName = name;

        // 创建用户界面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 主分隔面板
                mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                //上方面板
                upSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                upSplitPane.setEnabled(false); // 禁止拖动

                // 配置面板
                configPanel = new ConfigPanel();
                BurpExtender.setConfigPanel(configPanel);

                // 任务栏面板
                apiTable = new ApiTable(ExtensionTab.this);
                upScrollPane = new JScrollPane(apiTable);

                // 前两列设置宽度 30px
                for (int i = 0; i < 2; i++) {
                    apiTable.getColumnModel().getColumn(i).setMaxWidth(30);
                }

                apiTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                        if (isSelected) {
                            c.setBackground(Color.decode(Constants.TAB_COLOR_SELECTED));
                        } else {
                            ExtensionTab apiTable = (ExtensionTab) table.getModel();
                            ApiTableData apiTableData = apiTable.getApiTable().getTableData().get(row);
                            if (apiTableData.isSubData) {
                                c.setBackground(Color.decode(Constants.TAB_COLOR_SUB_DATA));
                            } else {
                                c.setBackground(Color.decode(Constants.TAB_COLOR_MAIN_DATA));
                            }
                        }
                        return c;
                    }
                });

                // 请求与响应界面的分隔面板规则
                downSplitPane = new JSplitPane();
                downSplitPane.setResizeWeight(0.5D);

                // 请求的面板
                requestPanel = new JTabbedPane();
                requestTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);
                requestPanel.addTab("Request", requestTextEditor.getComponent());

                // 响应的面板
                responsePanel = new JTabbedPane();
                responseTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);
                responsePanel.addTab("Response", responseTextEditor.getComponent());

                // 自定义程序UI组件
                downSplitPane.add(requestPanel, "left");
                downSplitPane.add(responsePanel, "right");

                upSplitPane.add(configPanel, "left");
                upSplitPane.add(upScrollPane, "right");

                mainSplitPane.add(upSplitPane, "left");
                mainSplitPane.add(downSplitPane, "right");

                callbacks.customizeUiComponent(mainSplitPane);

                // 将自定义选项卡添加到Burp的UI
                callbacks.addSuiteTab(ExtensionTab.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return mainSplitPane;
    }

    @Override
    public int getRowCount() {
        return this.getApiTable().getTableData().size();
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return " ";
            case 1:
                return "#";
            case 2:
                return "URL";
            case 3:
                return "Status Code";
            case 4:
                return "Event Name";
            case 5:
                return "Unauth";
            case 6:
                return "Scan Time";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ApiTableData data = this.getApiTable().getTableData().get(rowIndex);
        switch (columnIndex) {
            case 0:
                return data.treeStatus;
            case 1:
                return data.id;
            case 2:
                return data.url;
            case 3:
                return data.statusCode;
            case 4:
                return data.apiType;
            case 5:
                return data.unauth;
            case 6:
                return data.scanTime;
        }
        return null;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    /**
     * 新增任务至任务栏面板
     */
    public void add(ApiDocumentListTree apiDocumentListTree) {
        synchronized (this.apiTable) {
            this.apiTable.getTableData().add(apiDocumentListTree.getMainApiData());
            int _id = this.apiTable.getTableData().size();
            fireTableRowsInserted(_id, _id);
        }
    }

    public ApiTable getApiTable() {
        return this.apiTable;
    }

    /**
     * 界面显示数据存储模块
     */
    public static class ApiTableData {
        final String id;
        final String url;
        final String statusCode;
        final String apiType;
        final String unauth;
        final IHttpRequestResponse requestResponse;
        final String scanTime;
        final Boolean isSubData;
        final ApiDocumentListTree parentListTree;
        private String treeStatus = "";

        public ApiTableData(Boolean isSubData, ApiDocumentListTree parentListTree, String id, String url, String statusCode, String apiType, String unauth, IHttpRequestResponse requestResponse, String scanTime) {
            this.isSubData = isSubData;
            this.parentListTree = parentListTree;

            this.id = id;
            this.url = url;
            this.statusCode = statusCode;
            this.apiType = apiType;
            this.unauth = unauth;
            this.requestResponse = requestResponse;
            this.scanTime = scanTime;
        }

        public void setTreeStatus(String treeStatus) {
            this.treeStatus = treeStatus;
        }
    }

    /**
     * 自定义Table
     */
    public class ApiTable extends JTable {
        private final List<ApiTableData> tableData = new ArrayList<ApiTableData>();

        public ApiTable(TableModel tableModel) {
            super(tableModel);
        }

        public List<ApiTableData> getTableData() {
            return this.tableData;
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            ApiTableData dataEntry = ExtensionTab.ApiTable.this.tableData.get(convertRowIndexToModel(row));

            if (!dataEntry.isSubData) { // 切换状态
                if (dataEntry.parentListTree.getExpandStatus()) {
                    dataEntry.parentListTree.collapse();
                } else {
                    dataEntry.parentListTree.expand();
                }
            }

            requestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            responseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }
}
