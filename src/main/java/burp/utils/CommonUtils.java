package burp.utils;

import burp.BurpExtender;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

public class CommonUtils {
    /**
     * 获取当前第一级路径的 URL,  比如访问/xxx/xxx/aaa  返回的是/xxx
     */
    public static String getUrlWithPath(URL url) {

        String urlRootPath = getUrlRootPath(url);
        try {
            URL tmpurl = new URL(getUrlWithoutFilename(url));
            String path = tmpurl.getPath();
            while (path.startsWith("/")) {
                path = path.substring(1);
            }
            if (path.isEmpty()) {
                return urlRootPath;
            } else {
                return urlRootPath + "/" + path.substring(0, path.indexOf("/"));
            }
        } catch (MalformedURLException e) {
            BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
            return urlRootPath;
        }
    }

    /**
     * 获取根目录的 URL
     */
    public static String getUrlRootPath(URL url) {
        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
    }

    /*
     * http://host:port/path/file.jpg -> http://host:port/path/
     */
    public static String getUrlWithoutFilename(URL url) {
        String urlRootPath = getUrlRootPath(url);
        String path = url.getPath();

        if (path.length() == 0) {
            path = "/";
        }

        if (url.getFile().endsWith("/?format=openapi")) { //对django swagger做单独处理
            return urlRootPath + url.getFile();
        }

        if (path.endsWith("/")) {
            return urlRootPath + path;
        } else {
            return urlRootPath + path.substring(0, path.lastIndexOf("/") + 1);
        }
    }

    public static String getCurrentDateTime() {
        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(d);
    }

    public static byte[] getHttpRequestBody(byte[] request) {
        int bodyOffset = -1;

        IRequestInfo analyzeRequest = BurpExtender.getHelpers().analyzeRequest(request);
        bodyOffset = analyzeRequest.getBodyOffset();

        //not length-1;
        return Arrays.copyOfRange(request, bodyOffset, request.length);
    }

    public static byte[] getHttpResponseBody(byte[] response) {
        int bodyOffset = -1;

        IResponseInfo analyzeResponse = BurpExtender.getHelpers().analyzeResponse(response);
        bodyOffset = analyzeResponse.getBodyOffset();

        //not length-1;
        return Arrays.copyOfRange(response, bodyOffset, response.length);
    }

    public static <E> E randomChoice(Collection<? extends E> input) {
        int idx = new SecureRandom().nextInt(input.size());
        Iterator<? extends E> iterator = input.iterator();

        if (input instanceof List) { // optimization
            return ((List<? extends E>) input).get(idx);
        } else {
            Iterator<? extends E> iter = input.iterator();
            for (int i = 0; i < idx; i++) {
                iter.next();
            }
            return iter.next();
        }
    }

    public static String exceptionToString(Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }
}
