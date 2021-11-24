package burp.application.apitypes.soap;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.application.apitypes.ApiEndpoint;
import burp.utils.HttpRequestResponse;
import com.predic8.wsdl.*;
import com.predic8.wstool.creator.RequestTemplateCreator;
import com.predic8.wstool.creator.SOARequestCreator;
import groovy.xml.MarkupBuilder;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

public class WsdlParser {
    public static ArrayList<ApiEndpoint> parseWsdl(IHttpRequestResponse apiDocument) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();

        WSDLParser parser = new WSDLParser();
        Definitions definitions = parser.parse(helpers.analyzeRequest(apiDocument).getUrl().toString());

        List<Service> services = definitions.getServices();
        ArrayList<ApiEndpoint> apiEndpoints = new ArrayList<>();

        List<String> headers = helpers.analyzeRequest(apiDocument.getRequest()).getHeaders();
        List<String> httpFirstLine = Arrays.asList(headers.get(0).split(" "));
        httpFirstLine.set(0, "POST");
        headers.set(0, String.join(" ", httpFirstLine));

        HashSet<String> deleteHeader = new HashSet<>(Arrays.asList("soapaction", "content-type"));

        List<String> newHeaders = new ArrayList<>();
        newHeaders.add(String.join(" ", httpFirstLine));

        newHeaders.addAll(headers.subList(1, headers.size()).stream().filter(
                header -> !deleteHeader.contains(header.toLowerCase().split(":", 2)[0])
        ).collect(Collectors.toList())); //去掉 SOAPAction, Content-Type 这两个 header

        newHeaders.add("Content-Type: text/xml;charset=UTF-8");

        for (Service service : services) {
            for (Port port : service.getPorts()) {
                for (BindingOperation operation : port.getBinding().getOperations()) {
                    byte[] apiRequest = null;

                    try {
                        StringWriter writer = new StringWriter();

                        SOARequestCreator creator = new SOARequestCreator(definitions, new RequestTemplateCreator(), new MarkupBuilder(writer));
                        creator.createRequest(port.getName(), operation.getName(), port.getBinding().getName());

                        List<String> tempHeaders = new ArrayList<>(newHeaders);
                        tempHeaders.add("SOAPAction: " + operation.getOperation().getSoapAction());

                        apiRequest = helpers.buildHttpMessage(tempHeaders, writer.toString().getBytes());
                    } catch (Exception e) {
                        continue; // 解析出错一般直接跳过即可
                    }

                    HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                    tempRequestResponse.setHttpService(apiDocument.getHttpService());
                    tempRequestResponse.setRequest(apiRequest);
                    tempRequestResponse.sendRequest();

                    apiEndpoints.add(new ApiEndpoint(operation.getName(), tempRequestResponse));
                }
            }
        }

        return apiEndpoints;
    }
}
