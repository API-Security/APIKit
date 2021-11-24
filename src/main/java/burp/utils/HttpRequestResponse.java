package burp.utils;

import burp.BurpExtender;
import burp.CookieManager;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

public class HttpRequestResponse implements IHttpRequestResponse {
    byte[] request;
    byte[] response;
    String comment;
    IHttpService httpService;

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void sendRequest() {
        // 如果开启自动发送, 发出请求, 否则设置为空
        if (BurpExtender.getConfigPanel().getAutoSendRequest()) {
            this.setRequest(CookieManager.getRequest(httpService, request));
            this.setResponse("Loading...".getBytes());

            CompletableFuture.supplyAsync(() -> {
                try {
                    IHttpRequestResponse newHttpRequestResponse = BurpExtender.getCallbacks().makeHttpRequest(httpService, request);
                    this.setResponse(newHttpRequestResponse.getResponse());
                } catch (Exception e) {
                    BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
                    this.setResponse(CommonUtils.exceptionToString(e).getBytes());
                }
                return null;
            }, Executor.getExecutor());
        } else {
            this.setResponse("Auto request sending disabled".getBytes());
        }
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] response) {
        this.response = response;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return "";
    }

    @Override
    public void setHighlight(String s) {

    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}
