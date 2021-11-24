package burp.application.apitypes.actuator;

import burp.*;
import burp.application.apitypes.ApiEndpoint;
import burp.application.apitypes.ApiType;
import burp.exceptions.ApiKitRuntimeException;
import burp.utils.CommonUtils;
import burp.utils.HttpRequestResponse;
import burp.utils.UrlScanCount;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiTypeActuator extends ApiType {
    // 静态对象, 起到防止重复的作用
    private static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeActuator(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("SpringbootActuator");
        this.callbacks = BurpExtender.getCallbacks();
        this.helpers = BurpExtender.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeActuator(requestResponse, isPassive);
    }

    @Override
    public Boolean isFingerprintMatch() {
        URL url = helpers.analyzeRequest(this.baseRequestResponse).getUrl();

        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String urlWithPath = CommonUtils.getUrlWithPath(url);

        ArrayList<String> urlList = new ArrayList<>();

        if (scannedUrl.get(urlRootPath) <= 0 || !isPassive) {
            urlList.add(urlRootPath);
            if (isPassive)
                scannedUrl.add(urlRootPath);
        }

        if (scannedUrl.get(urlWithPath) <= 0 || !isPassive) {
            urlList.add(urlWithPath);
            if (isPassive)
                scannedUrl.add(urlWithPath);
        }

        for (String urlPath : urlList) {
            if (!urlAddPath(urlPath + "/actuator")) {
                urlAddPath(urlPath + "/mappings");
            }
        }

        return this.getApiDocuments().size() != 0;  // 不等于 0 代表找到了 API 文档
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        byte[] newRequest = null;

        try {
            newRequest = helpers.buildHttpRequest(new URL(apiDocumentUrl));
        } catch (MalformedURLException exception) {
            throw new ApiKitRuntimeException(exception);
        }
        IHttpRequestResponse newHttpRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
        String urlPath = helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString();
        if (helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
            if (this.isPassive) {
                if (scannedUrl.get(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                    scannedUrl.add(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                } else {
                    return false;
                }
            }
            String resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));
            try {
                JsonElement element = JsonParser.parseString(resp);
                if (element.isJsonObject()) {
                    JsonObject jsonObject = element.getAsJsonObject();  // 转化为对象
                    if (!(jsonObject.get("_links") == null) || !(jsonObject.get("/**/favicon.ico") == null) || !(jsonObject.get("contexts") == null)) {
                        if (!(jsonObject.get("_links") == null)) {
                            if (!(jsonObject.get("_links").getAsJsonObject().get("mappings") == null)) {
                                urlAddPath(urlPath + "/mappings");
                            }
                        }
                        this.getApiDocuments().put(apiDocumentUrl, newHttpRequestResponse);
                        return true;
                    }
                }
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }


    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        String urlRootPath = CommonUtils.getUrlRootPath(helpers.analyzeRequest(this.baseRequestResponse).getUrl());
        ArrayList<ApiEndpoint> results = new ArrayList<>();
        Pattern pattern = Pattern.compile("(\\[[^\\]]*\\])");
        Pattern patternpath = Pattern.compile("\"(\\/[a-zA-Z/]*)\"");
        byte[] newRequest = null;
        try {
            String body = new String(CommonUtils.getHttpResponseBody(apiDocument.getResponse()));
            JsonElement element = JsonParser.parseString(body);
            if (element.isJsonObject()) {
                JsonObject jsonObject = element.getAsJsonObject();  // 转化为对象
                if (!(jsonObject.get("_links") == null)) { //   springboot 2.x  /actuator
                    JsonObject links = jsonObject.get("_links").getAsJsonObject();
                    Set<Map.Entry<String, JsonElement>> endpoints = links.entrySet();
                    for (Map.Entry<String, JsonElement> endpoint : endpoints) {
                        String href = endpoint.getValue().getAsJsonObject().get("href").getAsString();
                        String uri = new URL(href).getPath();
                        if (href.contains("{") || href.contains("}")) {
                            continue;
                        }
                        try {
                            newRequest = helpers.buildHttpRequest(new URL(href));
                            newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
                            HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                            tempRequestResponse.setHttpService(apiDocument.getHttpService());
                            tempRequestResponse.setRequest(newRequest);
                            tempRequestResponse.sendRequest();
                            results.add(new ApiEndpoint(uri, tempRequestResponse));
                        } catch (MalformedURLException exception) {
                            throw new ApiKitRuntimeException(exception);
                        }
                    }
                } else if (!(jsonObject.get("/**/favicon.ico") == null)) { //  springboot 1.x  /mappings
                    try {
                        Set<Map.Entry<String, JsonElement>> endpoints = jsonObject.entrySet();
                        for (Map.Entry<String, JsonElement> endpoint : endpoints) {
                            String href = "";
                            String path = "";
                            try {
                                Matcher matcher = pattern.matcher(endpoint.getKey());
                                while (matcher.find()) {
                                    path = matcher.group().split(" ")[0];
                                    path = path.endsWith("]") ? path.substring(1, path.length() - 1) : path.substring(1, path.length());
                                    href = urlRootPath + path;
                                    if (href.contains("{") || href.contains("}")) {
                                        break;
                                    }
                                    while (href.endsWith("*")) {
                                        href = href.substring(0, href.length() - 1);
                                    }
                                    try {
                                        newRequest = helpers.buildHttpRequest(new URL(href));
                                        newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
                                        HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                                        tempRequestResponse.setHttpService(apiDocument.getHttpService());
                                        tempRequestResponse.setRequest(newRequest);
                                        tempRequestResponse.sendRequest();
                                        results.add(new ApiEndpoint(path, tempRequestResponse));
                                    } catch (MalformedURLException exception) {
                                        throw new ApiKitRuntimeException(exception);
                                    }
                                    break;
                                }
                            } catch (Exception eee) {

                            }

                        }
                    } catch (Exception ee) {
                        BurpExtender.getStderr().println(CommonUtils.exceptionToString(ee));
                    }
                } else if (!(jsonObject.get("contexts") == null)) {        //  springboot 2.x  /mappings
                    Matcher matcher = patternpath.matcher(body);
                    String href = "";
                    String uri = "";
                    while (matcher.find()) {
                        if (!matcher.group(1).endsWith("/")) {
                            href = urlRootPath + matcher.group(1);
                            uri = matcher.group(1);
                            try {

                                newRequest = helpers.buildHttpRequest(new URL(href));
                                newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
                                HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                                tempRequestResponse.setHttpService(apiDocument.getHttpService());
                                tempRequestResponse.setRequest(newRequest);
                                tempRequestResponse.sendRequest();
                                results.add(new ApiEndpoint(uri, tempRequestResponse));
                            } catch (MalformedURLException exception) {
                                throw new ApiKitRuntimeException(exception);
                            }
                        }
                    }

                }

            }
        } catch (Exception e) {
            BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
        }
        return results;
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
