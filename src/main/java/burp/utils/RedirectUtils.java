package burp.utils;

import burp.*;
import burp.exceptions.ApiKitRuntimeException;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

public class RedirectUtils {
    static final int maxRedirectCount = 16;
    private IHttpService currentHttpService;
    private IHttpRequestResponse currHttpRequestResponse;
    private String currUrl;
    private int redirectCount = 0;

    public RedirectUtils(IHttpRequestResponse httpRequestResponse) {
        this.currHttpRequestResponse = httpRequestResponse;
        this.currentHttpService = httpRequestResponse.getHttpService();
        this.currUrl = BurpExtender.getHelpers().analyzeRequest(httpRequestResponse).getUrl().toString();
    }

    public static String handleRelativeRedirectedUrl(String currentUrl, String locationUrl) {
        String result = null;
        try {
            URL currentUrlObject = new URL(currentUrl);

            int port = currentUrlObject.getPort();
            if (port == -1) {
                if ("https".equals(currentUrlObject.getProtocol())) {
                    port = 443;
                } else {
                    port = 80;
                }
            }

            if (locationUrl.startsWith("/")) {
                result = currentUrlObject.getProtocol() + "://" + currentUrlObject.getHost() + ":" + port + locationUrl;
            } else {
                String currentPath = currentUrlObject.getPath();
                if (!currentPath.endsWith("/")) {
                    currentPath = Paths.get(currentPath).getParent().toString();
                }

                String newPath = Paths.get(currentPath, locationUrl).toString();
                result = currentUrlObject.getProtocol() + "://" + currentUrlObject.getHost() + ":" + port + newPath;
            }
        } catch (MalformedURLException ignored) {
            throw new ApiKitRuntimeException("URL parse error");
        }
        return result;
    }

    public static IHttpService handleAbsoluteRedirectedUrl(String locationUrl) {
        IHttpService httpService = null;
        try {
            URL tempUrl = new URL(locationUrl); // 设置新的 HttpService
            int port = tempUrl.getPort();
            if (port == -1) {
                if ("https".equals(tempUrl.getProtocol())) {
                    port = 443;
                } else {
                    port = 80;
                }
            }
            httpService = BurpExtender.getHelpers().buildHttpService(tempUrl.getHost(), port, tempUrl.getProtocol());
        } catch (MalformedURLException ignored) {
            throw new ApiKitRuntimeException("URL parse error");
        }
        return httpService;
    }

    public static boolean isRedirectedResponse(IHttpRequestResponse httpRequestResponse) {
        if (!(httpRequestResponse.getResponse().length == 0 || httpRequestResponse.getResponse() == null))
            return String.valueOf(BurpExtender.getCallbacks().getHelpers().analyzeResponse(httpRequestResponse.getResponse()).getStatusCode()).startsWith("30");
        return false;
    }

    public static IHttpRequestResponse getRedirectedResponse(IHttpRequestResponse httpRequestResponse) {
        RedirectUtils redirectUtils = new RedirectUtils(httpRequestResponse);
        return redirectUtils.getFinalHttpRequestResponse();
    }

    public IHttpRequestResponse getFinalHttpRequestResponse() {
        IExtensionHelpers helpers = BurpExtender.getHelpers();

        try {
            while (String.valueOf(helpers.analyzeResponse(currHttpRequestResponse.getResponse()).getStatusCode()).startsWith("30")) {
                redirectCount += 1;
                if (redirectCount > maxRedirectCount) {
                    return null;
                }

                List<String> headers = helpers.analyzeResponse(currHttpRequestResponse.getResponse()).getHeaders();
                List<String> locationHeader = headers.stream().filter(header -> header.toLowerCase().startsWith("location:")).collect(Collectors.toList());
                if (locationHeader.size() > 0) {
                    // 有多个 Location, 取第一个
                    String newLocation = locationHeader.get(0);
                    newLocation = newLocation.substring("location:".length()).trim();

                    if (newLocation.startsWith("http://") || newLocation.startsWith("https://")) {
                        // 绝对地址
                        this.currentHttpService = RedirectUtils.handleAbsoluteRedirectedUrl(newLocation);
                    } else {
                        newLocation = RedirectUtils.handleRelativeRedirectedUrl(this.currUrl, newLocation);
                    }
                    this.currUrl = newLocation;
                    this.currHttpRequestResponse = CookieManager.makeHttpRequest(this.currentHttpService, helpers.buildHttpRequest(new URL(newLocation)));
                } else {
                    // 30x 但是没有 Location
                    return null;
                }
            }
            // 不是 30x 重定向, 返回
            return this.currHttpRequestResponse;
        } catch (Exception e) {
            return null;
        }
    }
}
