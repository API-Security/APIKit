package burp.application;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.application.apitypes.ApiType;
import burp.application.apitypes.actuator.ApiTypeActuator;
import burp.application.apitypes.graphql.ApiTypeGraphQL;
import burp.application.apitypes.soap.ApiTypeSoap;
import burp.application.apitypes.swagger.ApiTypeSwagger;
import burp.utils.CommonUtils;

import java.util.ArrayList;
import java.util.function.BiFunction;

public class ApiScanner {
    private final ArrayList<BiFunction<IHttpRequestResponse, Boolean, ApiType>> apiTypeConstructors = new ArrayList<>();

    public ApiScanner() {
        this.apiTypeConstructors.add(ApiTypeActuator::newInstance);
        this.apiTypeConstructors.add(ApiTypeSwagger::newInstance);
        this.apiTypeConstructors.add(ApiTypeGraphQL::newInstance);
        this.apiTypeConstructors.add(ApiTypeSoap::newInstance);
    }

    public ArrayList<ApiType> detect(IHttpRequestResponse baseRequestResponse, boolean isPassive) {
        ArrayList<ApiType> apiTypes = new ArrayList<>();
        for (BiFunction<IHttpRequestResponse, Boolean, ApiType> apiTypeConstructor : apiTypeConstructors) {
            try {
                ApiType apiType = apiTypeConstructor.apply(baseRequestResponse, isPassive);
                if (apiType.isFingerprintMatch()) {
                    apiTypes.add(apiType);
                }
            } catch (Exception e) {
                BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
            }
        }
        return apiTypes;
    }
}
