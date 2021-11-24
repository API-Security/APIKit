package burp.application.apitypes.swagger;

import burp.*;
import burp.application.apitypes.ApiEndpoint;
import burp.application.apitypes.ApiType;
import burp.exceptions.ApiKitRuntimeException;
import burp.utils.CommonUtils;
import burp.utils.HttpRequestResponse;
import burp.utils.RedirectUtils;
import burp.utils.UrlScanCount;
import com.google.gson.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiTypeSwagger extends ApiType {
    // 静态对象, 起到防止重复的作用
    private static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeSwagger(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("OpenAPI-Swagger");
        this.callbacks = BurpExtender.getCallbacks();
        this.helpers = BurpExtender.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeSwagger(requestResponse, isPassive);
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
            //只有java的swagger才有/swagger-resources   openapi 1 2 3 皆是如此
            Boolean result = urlAddPath(urlPath + "/swagger-resources");
            if (result != null && !result) { // 不重复且 urlAddPath 返回 false
                //访问html
                //常见设置的swagger路由 beego等
                urlAddPath(urlPath + "/swagger/");
                urlAddPath(urlPath + "/api/");
                //python swagger flasgger
                urlAddPath(urlPath + "/apidocs/");
                //
                urlAddPath(urlPath + "/");
            }
        }

        return this.getApiDocuments().size() != 0;  // 不等于 0 代表找到了 API 文档
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {

        IHttpService httpService = this.baseRequestResponse.getHttpService();
        IHttpRequestResponse newHttpRequestResponse;
        byte[] newRequest = null;
        boolean isapiobject = false;

        if (apiDocumentUrl.equals(helpers.analyzeRequest(this.baseRequestResponse).getUrl().toString())) {
            newHttpRequestResponse = this.baseRequestResponse;
        } else {
            try {
                newRequest = helpers.buildHttpRequest(new URL(apiDocumentUrl));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
            newHttpRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
        }

        String urlPath = CommonUtils.getUrlRootPath(helpers.analyzeRequest(newHttpRequestResponse).getUrl());

        //跟随跳转
        if (RedirectUtils.isRedirectedResponse(newHttpRequestResponse)) {
            newHttpRequestResponse = RedirectUtils.getRedirectedResponse(newHttpRequestResponse);
        }


        //访问的/swagger-resources 和 swagger2 的/api-docs 等如果不是200 则返回false
        if (helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
            if (this.isPassive) {
                if (scannedUrl.get(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                    scannedUrl.add(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                } else {
                    return false;
                }
            }

            String resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));
            JsonElement element = null;


            try {
                //尝试是否是json格式，如果是则转为gson元素
                element = JsonParser.parseString(resp);
            } catch (Exception e) {
            }

            try {
                //尝试是否是yaml格式,如果是则转为gson元素
                Yaml yaml = new Yaml(new SafeConstructor());
                Object result = yaml.load(resp);
                Gson gson = new GsonBuilder().create();
                element = gson.toJsonTree(result);
            } catch (Exception e) {
            }

            if (element != null) {
                // /swagger-resources  openapi 2.x [{"name":"default","location":"/v2/api-docs","swaggerVersion":"2.0"}]
                if (element.isJsonArray()) {
                    JsonArray ja = element.getAsJsonArray();
                    if (null != ja) {
                        for (JsonElement ae : ja) {
                            if (ae.isJsonObject()) {
                                JsonObject link = ae.getAsJsonObject();
                                // openapi 1 2 3 都可以从location中取。
                                if (!(link.get("location") == null)) {
                                    try {
                                        String tmpurl = URLEncoder.encode(link.get("location").getAsString(), "utf-8");
                                        tmpurl = tmpurl.replace("%2F", "/").replace("%3D", "=").replace("%3F", "?").replace("%40", "@").replace("%3A", ":");


                                        urlAddPath(urlPath + tmpurl);
                                    } catch (UnsupportedEncodingException e) {
                                        BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
                                    }
                                }
                            }
                        }
                    }
                    // /v2/api-docs  {"swagger":"2.0","info":{"description":"test","version":"1.0","title":"Java Swagger API 文档","license":{}},"host":"0.0.0.0:8091","basePath":"/","tags":[{"name":"deserialize","description":"Deserialize"},{"name":"filter-by-pass","description":"Filter By Pass"},{"name":"user-controller","description":"User Controller"},{"name":"commandi","description":"Commandi"}],"paths":{"/command/exec/array":{"post":{"tags":["commandi"],"summary":"命令执行","description":"exec接受array参数","operationId":"execArrayUsingPOST","consumes":["application/json"],"produces":["application/json"],"parameters":[{"in":"body","name":"path","description":"path","required":true,"schema":{"$ref":"#/definitions/
                    // /api-docs    {"apiVersion":"1.0","apis":[{"description":"Basic Error Controller","path":"/default/basic-error-controller","position":0},{"description":"Commandi","path":"/default/commandi","position":0},{"description":"Deserialize","path":"/default/deserialize","position":0},{"description":"Filter By Pass","path":"/default/filter-by-pass","position":0},{"description":"User Controller","path":"/default/user-controller","position":0}],"authorizations":{},"info":{"contact":"cor0ps","description":"漏洞仅仅做安全研究使用！","title":"Java Range API 文档"},"swaggerVersion":"1.2"}
                } else if (element.isJsonObject()) {
                    JsonObject link = element.getAsJsonObject();
                    // openapi 2.0 和openapi 3.0都是从 paths中取path
                    if (!(link.get("paths") == null)) {
                        if (link.get("paths").isJsonObject()) {
                            // 如果检测到是swagger 2 的json / yaml 文档  则加入接口文档列表。
                            if (!this.getApiDocuments().containsKey(apiDocumentUrl)) {
                                this.getApiDocuments().put(apiDocumentUrl, newHttpRequestResponse);
                                return true;
                            }
                        }
                    }
                    // openapi 1.2是从apis中取path
                    else if (!(link.get("apis") == null)) {
                        if (!(link.get("basePath") == null)) // basePath是/api-docs/ 和 /api-docs/{swaggerGroup}/{apiDeclaration} 区别
                            isapiobject = true;
                        if (link.get("apis").isJsonArray()) {
                            // 如果检测到是swagger 1.2 的文档   访问具体文档 /{swaggerGroup}/{apiDeclaration} 并将其加入接口文档列表。
                            JsonArray apisarray = link.get("apis").getAsJsonArray();
                            if (null != apisarray) {
                                for (JsonElement ae : apisarray) {
                                    if (ae.isJsonObject()) {
                                        JsonObject paths = ae.getAsJsonObject();
                                        if (!(paths.get("path") == null)) {

                                            if (isapiobject) { //api文档和子文档都有path  通过isapiobject判断是否是api子文档
                                                if (!this.getApiDocuments().containsKey(apiDocumentUrl)) {
                                                    this.getApiDocuments().put(apiDocumentUrl, newHttpRequestResponse);
                                                    return true;
                                                }
                                            } else
                                                //存在path且没有basePath时为 /api-docs/  访问具体文档 /{swaggerGroup}/{apiDeclaration}
                                                urlAddPath(apiDocumentUrl + paths.get("path").getAsString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                //正则去拿非java swagger html中的接口文档地址
                Pattern pattern = Pattern.compile("url:(\\s*)\"(.*?)\"");
                Pattern pattern2 = Pattern.compile("discoveryPaths:(\\s*)arrayFrom\\('(.*?)'\\)");
                Pattern pattern3 = Pattern.compile("\"url\":(\\s*)\"(.*?)\"");

                Matcher matcher = pattern.matcher(resp);
                Matcher matcher2 = pattern2.matcher(resp);
                Matcher matcher3 = pattern3.matcher(resp);
                String documentjsonyaml = "";
                while (matcher.find() || matcher2.find() || matcher3.find()) {
                    int count = 1;
                    while (count > 0) {
                        try {
                            documentjsonyaml = matcher.group(count);
                        } catch (Exception e) {
                            try {
                                documentjsonyaml = matcher2.group(count);
                            } catch (Exception ee) {
                                try {
                                    documentjsonyaml = matcher3.group(count);
                                } catch (Exception eee) {
                                    break;
                                }
                            }
                        }
                        count++;
                        if (documentjsonyaml.equals(" ") || documentjsonyaml.isEmpty())
                            continue;
                        if (documentjsonyaml.startsWith("./"))
                            urlAddPath(apiDocumentUrl + (apiDocumentUrl.endsWith("/") ? "" : "/") + documentjsonyaml.substring(2));
                            //如果是/开头说明可能是python swagger  不需要加/apidocs/路径
                        else if (documentjsonyaml.startsWith("/")) {
                            urlAddPath(urlPath + documentjsonyaml);
                        } else if (documentjsonyaml.startsWith("http")) {
                            urlAddPath(documentjsonyaml);
                        } else if (apiDocumentUrl.endsWith("/swagger/"))//像beego的swagger 则需要加上/swagger/路径
                            urlAddPath(apiDocumentUrl + documentjsonyaml);
                        else
                            //         若是根目录不带/  则判断后添加
                            urlAddPath(urlPath + "/" + documentjsonyaml);
                    }
                }
            }
        }
        return false;
    }


    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument) {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);
        //传入的是/api-docs 的json / yaml数据
        //String urlRootPath = CommonUtils.getUrlRootPath(helpers.analyzeRequest(this.baseRequestResponse).getUrl());
        ArrayList<ApiEndpoint> results = new ArrayList<>();
        List<String> headers = helpers.analyzeRequest(apiDocument.getRequest()).getHeaders();
        String body = new String(CommonUtils.getHttpResponseBody(apiDocument.getResponse()));
        byte[] newRequest = null;
        JsonElement jsonobject = null;
        try {
            jsonobject = JsonParser.parseString(body);
        } catch (Exception e) {
            stdout.println(e.getMessage());
        }
        try {
            Yaml yaml = new Yaml(new SafeConstructor());
            Object result = yaml.load(body);
            Gson gson = new GsonBuilder().create();
            jsonobject = gson.toJsonTree(result);
        } catch (Exception e) {
            stdout.println(e.getMessage());
        }

        if (jsonobject != null) {
            if (jsonobject.isJsonObject()) {
                try {
                    SwaggerObject swaggerObject = new SwaggerObject(headers);
                    swaggerObject.SwaggerParseObject(jsonobject.getAsJsonObject());
                    HashMap<List<String>, byte[]> apiRequest = swaggerObject.apiRequestResponse;
                    for (Map.Entry<List<String>, byte[]> apiReq : apiRequest.entrySet()) {

                        String uri = Arrays.asList(apiReq.getKey().get(0).split(" ")).get(1);
                        newRequest = helpers.buildHttpMessage(apiReq.getKey(), apiReq.getValue());
                        HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                        tempRequestResponse.setHttpService(apiDocument.getHttpService());
                        tempRequestResponse.setRequest(newRequest);
                        tempRequestResponse.sendRequest();
                        try {
                            results.add(new ApiEndpoint(uri, tempRequestResponse));
                        } catch (Exception e) {
                            stdout.println(e.getMessage());
                        }
                    }
                } catch (MalformedURLException e) {
                    BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
                }
            }
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
