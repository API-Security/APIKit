package burp.application.apitypes.soap;

import burp.*;
import burp.application.apitypes.ApiEndpoint;
import burp.application.apitypes.ApiType;
import burp.exceptions.ApiKitRuntimeException;
import burp.utils.CommonUtils;
import burp.utils.RedirectUtils;
import burp.utils.UrlScanCount;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiTypeSoap extends ApiType {
    // 静态对象, 起到防止重复的作用
    private static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeSoap(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("SOAP-WSDL");
        this.callbacks = BurpExtender.getCallbacks();
        this.helpers = BurpExtender.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeSoap(requestResponse, isPassive);
    }

    @Override
    public Boolean isFingerprintMatch() {
        URL url = helpers.analyzeRequest(this.baseRequestResponse).getUrl();

        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String urlWithPath = CommonUtils.getUrlWithPath(url);

        ArrayList<String> urlList = new ArrayList<>();

        if (scannedUrl.get(urlRootPath) <= 0 || !this.isPassive) {
            urlList.add(urlRootPath);
            if (this.isPassive)
                scannedUrl.add(urlRootPath);
        }

        if (scannedUrl.get(urlWithPath) <= 0 || !this.isPassive) {
            urlList.add(urlWithPath);
            if (this.isPassive)
                scannedUrl.add(urlWithPath);
        }
        urlAddPath(url.toString());
        for (String urlPath : urlList) {
            if (!urlAddPath(urlPath + "/service")) {
                urlAddPath(urlPath + "/services");
                urlAddPath(urlPath + "/webservices");
                urlAddPath(urlPath + "/webservice");
            }
        }

        return this.getApiDocuments().size() != 0;  // 不等于 0 代表找到了 API 文档
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        byte[] newRequest = null;
        IHttpRequestResponse newHttpRequestResponse;
        String urlorgin = helpers.analyzeRequest(this.baseRequestResponse).getUrl().toString();

        if (apiDocumentUrl.equals(urlorgin)) {
            newHttpRequestResponse = this.baseRequestResponse;
        } else {
            try {
                newRequest = helpers.buildHttpRequest(new URL(apiDocumentUrl));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
            newHttpRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
        }

        String currentUrl = helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString();
        String apidocument;

        //跟随跳转
        if (RedirectUtils.isRedirectedResponse(newHttpRequestResponse)) {
            newHttpRequestResponse = RedirectUtils.getRedirectedResponse(newHttpRequestResponse);
        }

        if (helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 500) {
            String resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));
            if (resp.contains("soap:Server")) { //cxf services 特征
                apidocument = currentUrl + (currentUrl.endsWith("/") ? "" : "/") + "?wsdl";
                try {
                    if (!this.getApiDocuments().containsKey(apidocument)) {
                        newRequest = helpers.buildHttpRequest(new URL(apidocument));
                        newHttpRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
                        this.getApiDocuments().put(apidocument, newHttpRequestResponse);
                        return true;
                    }
                } catch (MalformedURLException exception) {
                    throw new ApiKitRuntimeException(exception);
                }
            }
        }


        if (helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
            if (this.isPassive) {
                if (scannedUrl.get(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                    scannedUrl.add(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                } else {
                    return false;
                }
            }
            String resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));

            //cxf services axis2 axis1.4
            Pattern pattern = Pattern.compile("href=\"([^\"]*)\\?wsdl\">");
            Matcher matcher = pattern.matcher(resp);
            while (matcher.find()) {
                try {
                    apidocument = matcher.group(1);
                    if (apidocument.startsWith("http")) {
                        apidocument = apidocument + "?wsdl";
                    } else {
                        apidocument = helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString() + (helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString().endsWith("/") ? "" : "/") + apidocument + "?wsdl";
                    }
                    if (!this.getApiDocuments().containsKey(apidocument)) {
                        newRequest = helpers.buildHttpRequest(new URL(apidocument));
                        IHttpRequestResponse tempRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
                        this.getApiDocuments().put(apidocument, tempRequestResponse);
                    }
                } catch (Exception e) {
                }
            }
        }
        return this.getApiDocuments().size() != 0;
    }


    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument) {
        return WsdlParser.parseWsdl(apiDocument);
    }

    @Override
    public ArrayList<IScanIssue> exportIssues() {
        Iterator<Map.Entry<String, IHttpRequestResponse>> iterator = this.getApiDocuments().entrySet().iterator();
        ArrayList<IScanIssue> issues = new ArrayList<>();

        while (iterator.hasNext()) {
            Map.Entry<String, IHttpRequestResponse> entry = iterator.next();
            IHttpRequestResponse newHttpRequestResponse = entry.getValue();
            URL newHttpRequestUrl = helpers.analyzeRequest(newHttpRequestResponse).getUrl();

            String detail = String.format("<br/>============ ApiDetection ============<br/>");
            detail += String.format("API Technology Type: %s <br/>", this.getApiTypeName());
            detail += String.format("=====================================<br/>");
            issues.add(new CustomScanIssue(newHttpRequestResponse.getHttpService(), newHttpRequestUrl, new IHttpRequestResponse[]{newHttpRequestResponse}, "API Technology", detail, "Information"));
        }
        return issues;
    }

    @Override
    public String exportConsole() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("\n============== API 指纹详情 ============\n");
        stringBuilder.append("xxxx\n");
        stringBuilder.append("详情请查看 - Burp Scanner 模块 - Issue activity 界面\n");
        stringBuilder.append("===================================");
        return stringBuilder.toString();
    }
}
