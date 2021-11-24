package burp;

import burp.utils.CommonUtils;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CookieManager implements IHttpListener {
    // <origin: <key: value>>
    private final HashMap<String, HashMap<String, String>> cookies = new HashMap<>();

    public static byte[] getRequest(IHttpService httpService, byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();

        byte[] newRequest;

        IRequestInfo requestInfo = helpers.analyzeRequest(httpService, request);
        List<String> headers = requestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<>();

        newHeaders.add(headers.get(0));
        newHeaders.addAll(headers.subList(1, headers.size()).stream().filter(
                header -> !"cookie".equalsIgnoreCase(header.split(":", 2)[0])
        ).collect(Collectors.toList())); // 删掉 Cookie

        if (BurpExtender.getConfigPanel().getIncludeCookie()) {
            String cookieHeader = BurpExtender.getCookieManager().getCookieHeader(requestInfo.getUrl());
            if (cookieHeader != null) {
                newHeaders.add(cookieHeader);
            }

            newRequest = helpers.buildHttpMessage(newHeaders, CommonUtils.getHttpRequestBody(request));
        } else {
            newRequest = helpers.buildHttpMessage(newHeaders, CommonUtils.getHttpRequestBody(request));
        }
        return newRequest;
    }

    public static IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) {
        byte[] newRequest = CookieManager.getRequest(httpService, request);
        return BurpExtender.getCallbacks().makeHttpRequest(httpService, newRequest);
    }

    private String urlToOrigin(URL url) {
        int port = url.getPort();
        if (port == -1) {
            if ("http".equals(url.getProtocol())) {
                port = 80;
            } else {
                port = 443;
            }
        }
        return url.getProtocol() + "://" + url.getHost() + ":" + port;
    }

    private HashMap<String, String> parseCookie(String cookie) {
        HashMap<String, String> result = new HashMap<>();
        String[] keyValuePairs = cookie.split(";");

        for (String keyValuePair : keyValuePairs) {
            keyValuePair = keyValuePair.trim();
            String[] keyValue = keyValuePair.split("=", 2);

            if ("".equals(keyValue[0])) {
                continue; // 跳过空的 key
            }

            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
            } else {
                result.put(keyValue[0], "");
            }
        }
        return result;
    }

    private String joinCookieKeyValue(HashMap<String, String> cookie) {
        StringBuilder builder = new StringBuilder(new String());

        for (Map.Entry<String, String> entry : cookie.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            builder.append(key);
            builder.append("=");
            builder.append(value);
            builder.append("; ");
        }
        return builder.toString();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            // 更新 Cookie, 目前只实现了增加, 没有做删除的逻辑

            IRequestInfo requestInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo);
            String origin = this.urlToOrigin(requestInfo.getUrl());
            List<String> headers = requestInfo.getHeaders();

            // 找到所有的 Cookie Header
            List<String> cookies = headers.subList(1, headers.size()).stream().filter(
                    header -> "cookie".equalsIgnoreCase(header.split(":", 2)[0])
            ).collect(Collectors.toList());

            for (String cookieHeader : cookies) {
                String[] temp = cookieHeader.split(":", 2);
                if (temp.length == 2) {
                    HashMap<String, String> cookie = this.parseCookie(temp[1]);

                    // 合并 Cookie
                    if (this.cookies.get(origin) == null) {
                        this.cookies.put(origin, cookie);
                    } else {
                        this.cookies.get(origin).putAll(cookie);
                    }
                }
            }
        }
    }

    public String getCookieHeader(URL url) {
        HashMap<String, String> cookie = this.cookies.get(this.urlToOrigin(url));
        if (cookie != null) {
            return "Cookie: " + this.joinCookieKeyValue(cookie);
        } else {
            return null;
        }
    }
}
