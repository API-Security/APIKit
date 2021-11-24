package burp.application.apitypes;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * API 指纹扩展的抽象类
 * 所有的 API 指纹检测和遍历的方法都要继承它并实现所有的接口
 */
abstract public class ApiType implements ApiTypeInterface {
    private final HashMap<String, IHttpRequestResponse> ApiDocuments = new HashMap<>();
    protected Boolean isPassive;
    private String apiTypeName = "";

    /**
     * 获取扩展名称
     *
     * @return String
     */
    @Override
    public String getApiTypeName() {
        return this.apiTypeName;
    }

    /**
     * 设置扩展名称 (必须的)
     *
     * @param value
     */
    protected void setApiTypeName(String value) {
        this.apiTypeName = value;
    }

    /**
     * 获取 API 接口文档 URL 地址以及对应的请求/响应
     *
     * @return String
     */
    public HashMap<String, IHttpRequestResponse> getApiDocuments() {
        return this.ApiDocuments;
    }

    /**
     * 解析API文档中的API并遍历是否有鉴权。
     *
     * @return String
     */
    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument) {
        return null;
    }

    /**
     * 对传入的url遍历相应的path
     *
     * @param apiDocumentUrl
     */
    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        return false;
    }

    @Override
    public Boolean isFingerprintMatch() {
        return false;
    }
}
