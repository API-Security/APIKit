package burp.application.apitypes;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

import java.util.List;
import java.util.Map;

/**
 * API 指纹扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface ApiTypeInterface {
    String getApiTypeName();

    Boolean isFingerprintMatch();

    Map<String, IHttpRequestResponse> getApiDocuments();

    List<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument);

    List<IScanIssue> exportIssues();

    String exportConsole();

    Boolean urlAddPath(String apiDocumentUrl);
}