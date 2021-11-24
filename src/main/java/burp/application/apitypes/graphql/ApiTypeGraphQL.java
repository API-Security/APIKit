package burp.application.apitypes.graphql;

import burp.*;
import burp.application.apitypes.ApiEndpoint;
import burp.application.apitypes.ApiType;
import burp.exceptions.ApiKitRuntimeException;
import burp.utils.CommonUtils;
import burp.utils.Constants;
import burp.utils.HttpRequestResponse;
import burp.utils.UrlScanCount;
import com.google.gson.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class ApiTypeGraphQL extends ApiType {
    // 静态对象, 起到防止重复的作用
    private static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse baseRequestResponse;

    private final String graphQLIntrospectionRequestJSON = "cXVlcnkgUXVlcnkgewogICAgX19zY2hlbWEgewogICAgICBxdWVyeVR5cGUgeyBuYW1lIH0KICAgICAgbXV0YXRpb25UeXBlIHsgbmFtZSB9CiAgICAgIHN1YnNjcmlwdGlvblR5cGUgeyBuYW1lIH0KICAgICAgdHlwZXMgewogICAgICAgIC4uLkZ1bGxUeXBlCiAgICAgIH0KICAgICAgZGlyZWN0aXZlcyB7CiAgICAgICAgbmFtZQogICAgICAgIGRlc2NyaXB0aW9uCiAgICAgICAgbG9jYXRpb25zCiAgICAgICAgYXJncyB7CiAgICAgICAgICAuLi5JbnB1dFZhbHVlCiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQoKICBmcmFnbWVudCBGdWxsVHlwZSBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIGZpZWxkcyhpbmNsdWRlRGVwcmVjYXRlZDogdHJ1ZSkgewogICAgICBuYW1lCiAgICAgIGRlc2NyaXB0aW9uCiAgICAgIGFyZ3MgewogICAgICAgIC4uLklucHV0VmFsdWUKICAgICAgfQogICAgICB0eXBlIHsKICAgICAgICAuLi5UeXBlUmVmCiAgICAgIH0KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBpbnB1dEZpZWxkcyB7CiAgICAgIC4uLklucHV0VmFsdWUKICAgIH0KICAgIGludGVyZmFjZXMgewogICAgICAuLi5UeXBlUmVmCiAgICB9CiAgICBlbnVtVmFsdWVzKGluY2x1ZGVEZXByZWNhdGVkOiB0cnVlKSB7CiAgICAgIG5hbWUKICAgICAgZGVzY3JpcHRpb24KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBwb3NzaWJsZVR5cGVzIHsKICAgICAgLi4uVHlwZVJlZgogICAgfQogIH0KCiAgZnJhZ21lbnQgSW5wdXRWYWx1ZSBvbiBfX0lucHV0VmFsdWUgewogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIHR5cGUgeyAuLi5UeXBlUmVmIH0KICAgIGRlZmF1bHRWYWx1ZQogIH0KCiAgZnJhZ21lbnQgVHlwZVJlZiBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgb2ZUeXBlIHsKICAgICAga2luZAogICAgICBuYW1lCiAgICAgIG9mVHlwZSB7CiAgICAgICAga2luZAogICAgICAgIG5hbWUKICAgICAgICBvZlR5cGUgewogICAgICAgICAga2luZAogICAgICAgICAgbmFtZQogICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAga2luZAogICAgICAgICAgICBuYW1lCiAgICAgICAgICAgIG9mVHlwZSB7CiAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgIG5hbWUKICAgICAgICAgICAgICBvZlR5cGUgewogICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgbmFtZQogICAgICAgICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgICBuYW1lCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQ==";

    public ApiTypeGraphQL(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("GraphQLIntrospection");
        this.callbacks = BurpExtender.getCallbacks();
        this.helpers = BurpExtender.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeGraphQL(requestResponse, isPassive);
    }

    @Override
    public Boolean isFingerprintMatch() {
        URL url = helpers.analyzeRequest(this.baseRequestResponse).getUrl();

        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String urlWithPath = CommonUtils.getUrlWithPath(url);

        ArrayList<String> urlList = new ArrayList<>();

        if (scannedUrl.get(urlRootPath) <= 0 || !this.isPassive) {
            urlList.add(urlRootPath + "/graphql");
            urlList.add(urlRootPath + "/graphql.php");
            urlList.add(urlRootPath + "/graphiql");
            urlList.add(urlRootPath + "/graphiql.php");
            if (this.isPassive)
                scannedUrl.add(urlRootPath);
        }

        if (scannedUrl.get(urlWithPath) <= 0 || !this.isPassive) {
            urlList.add(urlWithPath + "/graphql");
            urlList.add(urlWithPath + "/graphql.php");
            urlList.add(urlWithPath + "/graphiql");
            urlList.add(urlWithPath + "/graphiql.php");
            if (this.isPassive)
                scannedUrl.add(urlWithPath);
        }

        for (String urlPath : urlList) {
            IHttpService httpService = this.baseRequestResponse.getHttpService();
            byte[] newRequest = null;

            try {
                newRequest = helpers.buildHttpRequest(new URL(urlPath));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }

            List<String> headers = helpers.analyzeRequest(newRequest).getHeaders();
            List<String> httpFirstLine = Arrays.asList(headers.get(0).split(" "));
            httpFirstLine.set(0, "POST");
            headers.set(0, String.join(" ", httpFirstLine));

            headers.add("Content-Type: application/json");
            //newRequest = helpers.toggleRequestMethod(newRequest);
            //IParameter parameter = helpers.buildParameter("", new String(), IParameter.PARAM_BODY);
            //newRequest = helpers.addParameter(newRequest, parameter);

            JsonObject jsonBody = new JsonObject();
            jsonBody.add("query", new JsonPrimitive(new String(helpers.base64Decode(this.graphQLIntrospectionRequestJSON))));
            newRequest = helpers.buildHttpMessage(headers, new Gson().toJson(jsonBody).getBytes());

            IHttpRequestResponse newHttpRequestResponse = CookieManager.makeHttpRequest(httpService, newRequest);
            if (helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
                if (this.isPassive) {
                    if (scannedUrl.get(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                        scannedUrl.add(helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                    } else {
                        return false;
                    }
                }
                String responseJSON = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));

                try {
                    JsonElement element = JsonParser.parseString(responseJSON);
                    if (element.isJsonObject()) {
                        JsonObject jsonObject = element.getAsJsonObject();
                        if (!jsonObject.get("data").isJsonNull() && !jsonObject.get("data").getAsJsonObject().get("__schema").isJsonNull()) {
                            this.getApiDocuments().put(urlPath, newHttpRequestResponse);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return this.getApiDocuments().size() != 0;  // 不等于 0 代表找到了 API 文档
    }

    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument) {
        String responseJSON = new String(CommonUtils.getHttpResponseBody(apiDocument.getResponse()));
        GraphQLParseResult parseResult = new GraphQLIntrospectionParser().parseIntrospection(responseJSON);

        ArrayList<ApiEndpoint> results = new ArrayList<>();

        // 处理 query 的 Object
        Set<Map.Entry<String, String>> endpoints = parseResult.queryParseResult.entrySet();

        for (Map.Entry<String, String> endpoint : endpoints) {
            URL url = helpers.analyzeRequest(apiDocument).getUrl();

            byte[] newRequest = null;
            try {
                newRequest = helpers.buildHttpRequest(new URL(url.toString()));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
            newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
            List<String> headers = helpers.analyzeRequest(newRequest).getHeaders();
            List<String> httpFirstLine = Arrays.asList(headers.get(0).split(" "));
            httpFirstLine.set(0, "POST");
            headers.set(0, String.join(" ", httpFirstLine));

            headers.add("Content-Type: application/json");

            JsonObject jsonBody = new JsonObject();
            jsonBody.add("query", new JsonPrimitive("query" + Constants.GRAPHQL_SPACE + endpoint.getKey() + Constants.GRAPHQL_SPACE + "{" + Constants.GRAPHQL_NEW_LINE + endpoint.getValue() + Constants.GRAPHQL_NEW_LINE + "}"));
            newRequest = helpers.buildHttpMessage(headers, new Gson().toJson(jsonBody).getBytes());
            newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
            HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
            tempRequestResponse.setHttpService(apiDocument.getHttpService());

            tempRequestResponse.setRequest(newRequest);
            tempRequestResponse.sendRequest();
            results.add(new ApiEndpoint("query:" + Constants.GRAPHQL_SPACE + endpoint.getKey(), tempRequestResponse));
        }

        // 处理 mutation 的 Object
        endpoints = parseResult.mutationParseResult.entrySet();

        for (Map.Entry<String, String> endpoint : endpoints) {
            URL url = helpers.analyzeRequest(apiDocument).getUrl();

            byte[] newRequest = null;
            try {
                newRequest = helpers.buildHttpRequest(new URL(url.toString()));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
            newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
            List<String> headers = helpers.analyzeRequest(newRequest).getHeaders();
            List<String> httpFirstLine = Arrays.asList(headers.get(0).split(" "));
            httpFirstLine.set(0, "POST");
            headers.set(0, String.join(" ", httpFirstLine));

            headers.add("Content-Type: application/json");

            JsonObject jsonBody = new JsonObject();
            jsonBody.add("query", new JsonPrimitive("mutation" + Constants.GRAPHQL_SPACE + endpoint.getKey() + Constants.GRAPHQL_SPACE + "{" + Constants.GRAPHQL_NEW_LINE + endpoint.getValue() + Constants.GRAPHQL_NEW_LINE + "}"));
            newRequest = helpers.buildHttpMessage(headers, new Gson().toJson(jsonBody).getBytes());
            newRequest = CookieManager.getRequest(apiDocument.getHttpService(), newRequest);
            HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
            tempRequestResponse.setHttpService(apiDocument.getHttpService());

            tempRequestResponse.setRequest(newRequest);
            tempRequestResponse.sendRequest();
            results.add(new ApiEndpoint("mutation:" + Constants.GRAPHQL_SPACE + endpoint.getKey(), tempRequestResponse));
        }

        return results;
    }

    @Override
    public List<IScanIssue> exportIssues() {
        return new ArrayList<>();
    }

    @Override
    public String exportConsole() {
        return "";
    }
}
