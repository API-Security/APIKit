package burp.ui;


import burp.utils.Constants;

import java.util.ArrayList;
import java.util.List;

public class ApiDocumentListTree {
    private ExtensionTab parent;
    private ExtensionTab.ApiTableData mainApiData;
    private ArrayList<ExtensionTab.ApiTableData> subApiData;
    private Boolean expandStatus = false; // true = 展开, false = 收起

    public ApiDocumentListTree(ExtensionTab parent) {
        this.parent = parent;
    }

    public void setSubApiData(ArrayList<ExtensionTab.ApiTableData> subApiData) {
        this.subApiData = subApiData;
    }

    public ExtensionTab.ApiTableData getMainApiData() {
        return this.mainApiData;
    }

    public void setMainApiData(ExtensionTab.ApiTableData mainApiData) {
        this.mainApiData = mainApiData;
    }

    public Boolean getExpandStatus() {
        return this.expandStatus;
    }

    public void expand() {
        if (!this.expandStatus) {
            this.mainApiData.setTreeStatus(Constants.TREE_STATUS_EXPAND);

            List<ExtensionTab.ApiTableData> apiTableData = this.parent.getApiTable().getTableData();
            int selfIndex = apiTableData.indexOf(this.mainApiData);

            for (int i = 0; i < subApiData.size(); i++) {
                ExtensionTab.ApiTableData data = subApiData.get(i);
                /*
                if (i != subApiData.size() - 1) {
                    data.setTreeStatus("┠");
                } else {
                    data.setTreeStatus("┗");
                }
                 */
                apiTableData.add(selfIndex + 1 + i, data);
            }
            int _id = apiTableData.size();
            parent.fireTableRowsInserted(selfIndex, _id);
        }
        this.expandStatus = true;
    }

    public void collapse() {
        if (this.expandStatus) {
            this.mainApiData.setTreeStatus(Constants.TREE_STATUS_COLLAPSE);
            List<ExtensionTab.ApiTableData> apiTableData = this.parent.getApiTable().getTableData();
            int selfIndex = apiTableData.indexOf(this.mainApiData);

            for (int i = 0; i < subApiData.size(); i++) {
                apiTableData.remove(selfIndex + 1);
            }
            int _id = apiTableData.size();
            parent.fireTableRowsInserted(selfIndex, _id);
        }
        this.expandStatus = false;
    }
}
