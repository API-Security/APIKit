package burp;

import burp.application.ApiScanner;
import burp.application.apitypes.ApiEndpoint;
import burp.application.apitypes.ApiType;
import burp.ui.ApiDocumentListTree;
import burp.ui.ExtensionTab;
import burp.utils.CommonUtils;
import burp.utils.Constants;
import burp.utils.UrlScanCount;

import java.net.URL;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class PassiveScanner implements IScannerCheck {
    private final UrlScanCount scanedUrl = new UrlScanCount();
    private final ApiScanner apiScanner;
    private int scannedCount = 1;

    public PassiveScanner() {
        this.apiScanner = new ApiScanner();
    }

    public ApiScanner getApiScanner() {
        return apiScanner;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse httpRequestResponse) {
        URL httpRequestURL = BurpExtender.getHelpers().analyzeRequest(httpRequestResponse).getUrl();
        String requestUrl = CommonUtils.getUrlWithoutFilename(httpRequestURL);

        // 目前检测的查重是将 http://user:pass@host:port/deep/path/filename?query#fragment
        // 归一化为 http://host:port/deep/path 后检测是否扫描过, 如果未来有对 query 有相关检测需求, 可以在修改 Common.getUrlWithoutFilename

        if (this.scanedUrl.get(requestUrl) <= 0) {
            this.scanedUrl.add(requestUrl);
        } else {
            return null; // 检测到重复, 直接返回
        }

        ArrayList<ApiType> apiTypes = this.apiScanner.detect(httpRequestResponse, true);
        return this.parseApiDocument(apiTypes);
    }

    public List<IScanIssue> parseApiDocument(ArrayList<ApiType> apiTypes) {
        List<IScanIssue> issues = new ArrayList<>();
        ExtensionTab extensionTab = BurpExtender.getExtensionTab();

        //遍历扫到的ApiType
        for (ApiType apiType : apiTypes) {
            Map<String, IHttpRequestResponse> apiDocuments = apiType.getApiDocuments();
            //遍历ApiType中的接口文档

            for (Map.Entry<String, IHttpRequestResponse> entry : apiDocuments.entrySet()) {
                ApiDocumentListTree apiDocumentListTree = new ApiDocumentListTree(extensionTab);

                ExtensionTab.ApiTableData mainApiData = new ExtensionTab.ApiTableData(false, apiDocumentListTree, String.valueOf(this.scannedCount), entry.getKey(), String.valueOf(BurpExtender.getHelpers().analyzeResponse(entry.getValue().getResponse()).getStatusCode()), apiType.getApiTypeName(), "true", entry.getValue(), CommonUtils.getCurrentDateTime());
                ArrayList<ExtensionTab.ApiTableData> subApiData = new ArrayList<>();

                mainApiData.setTreeStatus(Constants.TREE_STATUS_COLLAPSE);

                apiDocumentListTree.setMainApiData(mainApiData);
                apiDocumentListTree.setSubApiData(subApiData);

                // 排序
                List<ApiEndpoint> apiEndpoints = apiType.parseApiDocument(entry.getValue());
                apiEndpoints.sort(Comparator.comparing(ApiEndpoint::getUrl));

                // 遍历接口文档中的接口
                for (ApiEndpoint apiEndpoint : apiEndpoints) {
                    IHttpRequestResponse apiParseRequestResponse = apiEndpoint.getHttpRequestResponse();
                    ExtensionTab.ApiTableData currentData = new ExtensionTab.ApiTableData(true,
                            apiDocumentListTree,
                            "",
                            apiEndpoint.getUrl(),
                            String.valueOf(BurpExtender.getHelpers().analyzeResponse(apiParseRequestResponse.getResponse()).getStatusCode()),
                            apiType.getApiTypeName(),
                            (BurpExtender.getHelpers().analyzeResponse(apiParseRequestResponse.getResponse()).getStatusCode() != 200 && BurpExtender.getHelpers().analyzeResponse(apiParseRequestResponse.getResponse()).getStatusCode() != 405 && BurpExtender.getHelpers().analyzeResponse(apiParseRequestResponse.getResponse()).getStatusCode() != 500 ? "false" : "true"),
                            apiParseRequestResponse,
                            CommonUtils.getCurrentDateTime());

                    subApiData.add(currentData);
                }

                extensionTab.add(apiDocumentListTree);
                this.scannedCount++;
            }

            // API 指纹检测 - 报告输出
            issues.addAll(apiType.exportIssues());
            // API 指纹检测 - 控制台报告输出
            BurpExtender.getStdout().print(apiType.exportConsole());
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse httpRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}
