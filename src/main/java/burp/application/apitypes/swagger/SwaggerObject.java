package burp.application.apitypes.swagger;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SwaggerObject {
    final public String boundary = "----" + UUID.randomUUID().toString();
    final public String newLine = "\r\n";
    public String basePath;       //应用web路径
    public JsonObject definitions;// 外部定义的json对象
    public JsonObject link;       //swagger.json的根json对象
    public HashMap<String, String> params; //参数临时存储map
    public HashMap<List<String>, byte[]> apiRequestResponse;
    public String content_type;
    public String para_bodystr;
    public String para_querystr;
    public String in;
    public String method;
    public List<String> headers;
    public ArrayList<String> newheaders;
    public Stack<String> itemsStack = new Stack<>();
    public String uri;
    public String path;
    public boolean isctset;

    public SwaggerObject(List<String> headers) {
        this.headers = headers;
        basePath = "";
        params = new HashMap<>();
        newheaders = new ArrayList<>(headers);
        apiRequestResponse = new HashMap<>();
        method = "GET";
        para_querystr = "";
        para_bodystr = "";
        path = "";
        isctset = false;
    }

    public static String replaceStr(String testStr) {
        testStr = testStr.replace("\"*int64*\"", "1");
        testStr = testStr.replace("\"*int32*\"", "1");
        testStr = testStr.replace("\"*float*\"", "1");
        testStr = testStr.replace("\"*double*\"", "1");
        testStr = testStr.replace("\"int64\"", "2");
        testStr = testStr.replace("\"int32\"", "2");
        testStr = testStr.replace("\"float\"", "2.0");
        testStr = testStr.replace("\"double\"", "2.0");
        testStr = testStr.replace("*string*", "aaaa");
        testStr = testStr.replace("*int64*", "1");
        testStr = testStr.replace("*int32*", "1");
        testStr = testStr.replace("*float*", "1");
        testStr = testStr.replace("*double*", "1");
        testStr = testStr.replace("*byte*", "MTIzNDU2");
        testStr = testStr.replace("*binary*", "binary");
        testStr = testStr.replace("*date-time*", "2020-10-10T23:59:60");
        testStr = testStr.replace("*datetime*", "2020-10-10T23:59:60");
        testStr = testStr.replace("*date*", "23:59:60");
        testStr = testStr.replace("*password*", "password");
        testStr = testStr.replace("string", "test");
        testStr = testStr.replace("int64", "2");
        testStr = testStr.replace("int32", "2");
        testStr = testStr.replace("float", "2.0");
        testStr = testStr.replace("double", "2.0");
        testStr = testStr.replace("byte", "MTIz");
        testStr = testStr.replace("binary", "binary");
        testStr = testStr.replace("date-time", "2020-10-10T23:59:60");
        testStr = testStr.replace("datetime", "2020-10-10T23:59:60");
        testStr = testStr.replace("date", "23:59:60");
        testStr = testStr.replace("password", "password");
        testStr = testStr.replace("\"*integer*\"", "4");
        testStr = testStr.replace("\"*number*\"", "4.0");
        testStr = testStr.replace("*integer*", "4");
        testStr = testStr.replace("*number*", "4.0");
        testStr = testStr.replace("\"*boolean*\"", "false");
        testStr = testStr.replace("*boolean*", "false");
        testStr = testStr.replace("\"integer\"", "3");
        testStr = testStr.replace("\"number\"", "3.0");
        testStr = testStr.replace("integer", "3");
        testStr = testStr.replace("number", "3.0");
        testStr = testStr.replace("\"boolean\"", "true");
        testStr = testStr.replace("boolean", "true");
        testStr = testStr.replace("uuid", "11111111-0000-2222-3333-444444444444");

        return testStr;
    }

    /**
     * "paths":{"/command/exec/array":{"post":{"tags":["commandi"],"summary":"命令执行","description":"exec接受array参数","operationId":"execArrayUsingPOST","consumes":["application/json"],"produces":["application/json"],"parameters":[{
     */

    // openapi 1 2 3  swagger根对象初始化
    public HashMap<String, String> SwaggerParseObject(JsonObject inputJsonobj) throws MalformedURLException {
        link = inputJsonobj.getAsJsonObject();  // 转化为对象

        // openapi 1.2 和2.0 都可以直接取basePath  openapi3没有basePath
        if (!(link.get("basePath") == null)) {
            basePath = link.get("basePath").getAsString();
            if (basePath.equals("/"))
                basePath = basePath.substring(1);
        }
        //openapi3  basePath在 servers的url中，url如http:/xxx/v1 格式  可以使用相对路径  也可以使用变量的形式。
        if (!(link.get("servers") == null)) {
            String url = link.get("servers").getAsJsonArray().get(0).getAsJsonObject().get("url").getAsString();
            if (url.startsWith("/"))
                basePath = url;
            else {
                basePath = new URL(url).getPath();
            }
            if (url.contains("{")) {
                JsonObject servervariables = link.get("servers").getAsJsonObject().get("variables").getAsJsonObject();
                Set<Map.Entry<String, JsonElement>> servervariabless = servervariables.entrySet();
                //遍历variables下所有变量，并替换为default
                for (Map.Entry<String, JsonElement> servervariable : servervariabless) {
                    basePath = basePath.replace("{" + servervariable.getKey() + "}", servervariable.getValue().getAsJsonObject().get("default").getAsString());
                }
            }

            if (basePath.equals("/"))
                basePath = basePath.substring(1);
        }


        //以下为3.0  components相当于 2.0 的definitions
        //这里openapi3的外部文档只考虑最简单的schemas一种情况
        if (!(link.get("components") == null)) {
            definitions = link.get("components").getAsJsonObject();
            if (!(definitions.get("schemas") == null))
                definitions = definitions.get("schemas").getAsJsonObject();
        }

        //以下为1.2     models相当于 2.0 的definitions
        if (!(link.get("models") == null)) {
            definitions = link.get("models").getAsJsonObject();
        }
        if (!(link.get("apis") == null)) {
            if (link.get("apis").isJsonArray()) {
                JsonArray apisarray = link.get("apis").getAsJsonArray();
                if (null != apisarray) {
                    for (JsonElement ae : apisarray) {
                        if (ae.isJsonObject()) {
                            uri = basePath + ae.getAsJsonObject().get("path").getAsString();
                            boolean globals_content_type = false;
                            if (!(ae.getAsJsonObject().get("consumes") == null)) {
                                JsonArray content_types = ae.getAsJsonObject().get("consumes").getAsJsonArray();
                                content_type = content_types.get(0).getAsString();
                                globals_content_type = true;
                            }
                            if (!(ae.getAsJsonObject().get("operations") == null)) {
                                JsonArray operations = ae.getAsJsonObject().get("operations").getAsJsonArray();
                                if (!operations.isJsonNull()) {
                                    for (JsonElement operation : operations) {
                                        if (operation.isJsonObject()) {
                                            JsonObject op = operation.getAsJsonObject();
                                            //获取请求包的请求方法
                                            method = op.get("method").getAsString();

                                            if (!globals_content_type)
                                                content_type = "";
                                            if (!(op.get("consumes") == null)) {
                                                JsonArray content_types = op.get("consumes").getAsJsonArray();
                                                content_type = content_types.get(0).getAsString();
                                            }
                                            JsonArray parameters = op.get("parameters").getAsJsonArray();
                                            if (parameters.isJsonArray()) {
                                                isctset = false;
                                                for (JsonElement parameter : parameters) {
                                                    if (parameter.isJsonObject()) {
                                                        params.clear();
                                                        in = "";
                                                        Openapi1ParserObject("", parameter.getAsJsonObject());
                                                        makeHttpRequest();
                                                    }
                                                }
                                                if (parameters.size() == 0) {
                                                    cleanparam();
                                                    makeHttpRequest();
                                                }
                                                saveHttpRequest();
                                                para_querystr = "";
                                                para_bodystr = "";
                                                path = "";
                                            }
                                        }
                                    }
                                }

                            }
                        }
                    }
                }
            }
        }


        // 以下为2.0
        if (!(link.get("definitions") == null)) {
            definitions = link.get("definitions").getAsJsonObject();
        }
        // 3.0同样从paths中取path
        if (!(link.get("paths") == null)) {
            if (link.get("paths").isJsonObject()) {
                JsonObject paths = link.get("paths").getAsJsonObject();
                //获取接口url 2 3 相同
                Set<Map.Entry<String, JsonElement>> apiPaths = paths.getAsJsonObject().entrySet();
                //遍历接口下所有方法 get 、 post   apiPath<"uri",["get","post"]>
                for (Map.Entry<String, JsonElement> apiPath : apiPaths) {

                    uri = basePath + apiPath.getKey();
                    if (apiPath.getValue().isJsonObject()) {
                        //   apiMethod<"get",{"consumes":["application/json"],"parameters": json}>  获取http方法中的参数
                        for (Map.Entry<String, JsonElement> apiMethod : apiPath.getValue().getAsJsonObject().entrySet()) {
                            //获取请求包的请求方法
                            method = apiMethod.getKey().toUpperCase();

                            content_type = "";
                            if (apiMethod.getValue().isJsonObject()) {
                                //获取请求包的content-type  2.0从 consumes 中取
                                if (!(apiMethod.getValue().getAsJsonObject().get("consumes") == null)) {
                                    JsonArray content_types = apiMethod.getValue().getAsJsonObject().get("consumes").getAsJsonArray();
                                    if (content_types.size() != 0)
                                        content_type = content_types.get(0).getAsString();
                                }

                                //遍历参数  在openapi 2 3中 parameters可以和get同级 ，但是感觉一般不会这样写，因为要适用于所有这个路由下的方法，明显是非常特殊的情况
                                // openapi 3中 methoh下的parameters仅仅为"query", "header", "path" or "cookie" 提供 。 body中的parameters在requestBody中
                                boolean reqparamnull = true;
                                isctset = false;
                                if (!(apiMethod.getValue().getAsJsonObject().get("parameters") == null)) {
                                    reqparamnull = false;
                                    JsonArray apiParameters = apiMethod.getValue().getAsJsonObject().get("parameters").getAsJsonArray();
                                    if (apiParameters.size() == 0)
                                        reqparamnull = true;
                                    if (null != apiParameters) {

                                        for (JsonElement apiParameter : apiParameters) {
                                            if (!apiParameter.isJsonNull()) {
                                                params.clear();
                                                in = "";
                                                Openapi23ParserObject("", apiParameter.getAsJsonObject());
                                                makeHttpRequest();
                                            }
                                        }
                                    }
                                }

                                if (!(apiMethod.getValue().getAsJsonObject().get("requestBody") == null)) {
                                    reqparamnull = false;
                                    JsonObject reqest = apiMethod.getValue().getAsJsonObject().get("requestBody").getAsJsonObject().get("content").getAsJsonObject();
                                    isctset = false;
                                    //openapi 3 获取content-type
                                    Set<Map.Entry<String, JsonElement>> reqs = reqest.entrySet();
                                    //遍历该方法下所有content_type 和参数  "content":{"application/json":{"schema":{"$ref":"#/components/schemas/
                                    for (Map.Entry<String, JsonElement> req : reqs) {
                                        content_type = req.getKey();
                                        params.clear();
                                        in = "body";
                                        Openapi23ParserObject("", req.getValue().getAsJsonObject());
                                        makeHttpRequest();
                                        in = "";
                                        break;//有一个contenttype能用就行
                                    }

                                }
                                if (reqparamnull) { //当参数为空也要生成请求。
                                    cleanparam();
                                    makeHttpRequest();
                                }
                                saveHttpRequest();
                                para_querystr = "";
                                para_bodystr = "";
                                path = "";
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    private void cleanparam() {
        para_querystr = "";
        para_bodystr = "";
        content_type = "";
        path = "";
        params.clear();
        in = "";

    }

    // openapi 2.x  获取每个参数的name和format
    private void Openapi23ParserObject(String para_name, JsonObject apiParam) {
        String para_format = "";
        String is_required = "";
        //若传入的是Parameter Object 则取参数名name
        if (!(apiParam.get("name") == null)) {
            para_name = apiParam.get("name").getAsString();
        }
        //获取参数类型
        if (!(apiParam.get("in") == null)) {
            in = apiParam.get("in").getAsString().toLowerCase();
        }
        //查询参数是否可缺省
        if (!(apiParam.get("required") == null)) {
            if (apiParam.get("required").isJsonPrimitive())
                if (apiParam.get("required").getAsBoolean())
                    is_required = "*";
        } else {
            is_required = "";
        }

        //查询参数格式
        if (!(apiParam.get("format") == null)) {
            para_format = apiParam.get("format").getAsString();
        } else if (!(apiParam.get("schema") == null)) {
            if (apiParam.get("schema").getAsJsonObject().get("$ref") == null)
                Openapi23ParserObject(para_name, apiParam.get("schema").getAsJsonObject());
            else
                Openapi23ParserObject("", apiParam.get("schema").getAsJsonObject());
        } else if (!(apiParam.get("$ref") == null)) {
            //undefined = false;
            /**
             * "PathInfo":{"type":"object","properties":{"path":{"type":"string"},"type":{"type":"integer","format":"int32"}}}
             */

            //这里openapi3的外部文档只考虑最简单的schemas一种情况，还有responses、parameters、examples、requestBodies、headers等。
            String para_ref = apiParam.get("$ref").getAsString().replace("#/definitions/", "").replace("#/components/schemas/", "");
            //获取外部文档名
            if (definitions.isJsonObject())//判断是否有外部文档 避免报错
                if (!(definitions.get(para_ref) == null)) {//判断是否外部文档中有相关结构体定义
                    if (!(definitions.get(para_ref).getAsJsonObject().get("properties") == null)) {//判断是否外部文档中有相关结构体的参数定义
                        //使用栈避免互相定义导致递归
                        if (Collections.frequency(itemsStack, para_ref) <= 0) {
                            itemsStack.push(para_ref);
                            JsonObject properties = definitions.get(para_ref).getAsJsonObject().get("properties").getAsJsonObject();
                            //对properties内的多个body参数进行处理  因为只有body才有schema
                            Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                            for (Map.Entry<String, JsonElement> en : propertie) {
                                Openapi23ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                            }

                            itemsStack.pop();
                        }
                    }
                }
        } else if (!(apiParam.get("items") == null)) {
            if (!(apiParam.get("items").getAsJsonObject().get("$ref") == null)) {
                Openapi23ParserObject("", apiParam.get("items").getAsJsonObject());
            } else
                Openapi23ParserObject(para_name, apiParam.get("items").getAsJsonObject());

        } else if (!(apiParam.get("properties") == null)) {//openapi3 也可以不从外部文档取参数
            JsonObject properties = apiParam.get("properties").getAsJsonObject();
            for (Map.Entry<String, JsonElement> propert : properties.entrySet()) {
                Openapi23ParserObject(propert.getKey(), propert.getValue().getAsJsonObject());
            }
        } else if (!(apiParam.get("additionalProperties") == null)) {
            if (apiParam.get("additionalProperties").isJsonObject())
                Openapi23ParserObject(para_name, apiParam.get("additionalProperties").getAsJsonObject());
        } else if (!(apiParam.get("type") == null))
            para_format = apiParam.get("type").getAsString();
        else {
            para_format = "null";
        }

        //当成功获取到参数格式和参数名时put进params map
        if (!para_name.isEmpty() && !para_format.isEmpty() && !params.containsKey(para_name)) {
            params.put(para_name, is_required + para_format + is_required);
        }
    }

    // openapi 1.2  获取每个参数的name和format
    private void Openapi1ParserObject(String para_name, JsonObject apiParam) {

        String para_format = "";
        String is_required = "";
        String para_ref = "";
        //若传入的是Parameter Object 则取参数名name
        if (!(apiParam.get("name") == null)) {
            para_name = apiParam.get("name").getAsString();
        }
        //获取参数类型    1.2 paramType 相当于2.0的in
        if (!(apiParam.get("paramType") == null)) {
            in = apiParam.get("paramType").getAsString().toLowerCase();
        }

        //查询参数是否可缺省
        if (!(apiParam.get("required") == null)) {
            if (apiParam.get("required").getAsBoolean())
                is_required = "*";
        } else {
            is_required = "";
        }

//        //查询外部引用对象名
//        if (!(apiParam.get("type") == null)) {
//            para_ref = apiParam.get("type").getAsString();
//        }


        //查询参数格式
        if (!(apiParam.get("format") == null)) {
            para_format = apiParam.get("format").getAsString();
        } else if (!(apiParam.get("$ref") == null)) {
            //查询外部引用对象名
            para_ref = apiParam.get("$ref").getAsString();
            //获取外部文档名
            if (definitions.isJsonObject())//判断是否有外部文档 避免报错
                if (!(definitions.get(para_ref) == null)) {//判断是否外部文档中有相关结构体定义
                    if (!(definitions.get(para_ref).getAsJsonObject().get("properties") == null)) {//判断是否外部文档中有相关结构体的参数定义
                        //使用栈避免互相定义导致递归
                        if (Collections.frequency(itemsStack, para_ref) <= 0) {
                            itemsStack.push(para_ref);
                            JsonObject properties = definitions.get(para_ref).getAsJsonObject().get("properties").getAsJsonObject();
                            //对properties内的多个body参数进行处理
                            Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                            for (Map.Entry<String, JsonElement> en : propertie) {
                                Openapi1ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                            }
                            itemsStack.pop();
                        }
                    }
                }
        } else if (!(apiParam.get("items") == null)) {
            if (!(apiParam.get("items").getAsJsonObject().get("$ref") == null)) {
                Openapi1ParserObject("", apiParam.get("items").getAsJsonObject());
            } else
                Openapi1ParserObject(para_name, apiParam.get("items").getAsJsonObject());

        } else if (!(apiParam.get("type") == null)) {
            // openapi 1.2 type内容也可以作为外部引用文档
            para_format = apiParam.get("type").getAsString();
            if (definitions.isJsonObject())//判断是否有外部文档 避免报错
                if (!(definitions.get(para_format) == null)) {//判断是否外部文档中有相关结构体定义

                    if (!(definitions.get(para_format).getAsJsonObject().get("properties") == null)) {//判断是否外部文档中有相关结构体的参数定义

                        //使用栈避免互相定义导致递归
                        if (Collections.frequency(itemsStack, para_format) <= 0) {
                            itemsStack.push(para_format);
                            JsonObject properties = definitions.get(para_format).getAsJsonObject().get("properties").getAsJsonObject();
                            //对properties内的多个body参数进行处理
                            Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                            for (Map.Entry<String, JsonElement> en : propertie) {
                                Openapi1ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                            }
                            itemsStack.pop();
                        }
                    }
                    para_format = ""; // 进入外部文档后将format置空
                }
        } else {
            para_format = "null";
        }

        //当成功获取到参数格式和参数名时put进params map
        if (!para_name.isEmpty() && !para_format.isEmpty() && !params.containsKey(para_name)) {
            params.put(para_name, is_required + para_format + is_required);
        }
    }

    //构造每个参数在包中的位置
    public void makeHttpRequest() {
        //构造参数
        if (path.isEmpty())//当path为空的时候赋值uri     避免 /{aa}/替换之后再被覆盖
            path = uri;
        //isctset 用于判断是否已经根据发包类型添加contenttype
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String _para_name = entry.getKey();
            String _para_format = entry.getValue();
            boolean isupload = false;
            switch (in) {
                case "body":
                    if (content_type.isEmpty()) {
                        if (!isctset) {
                            isctset = true; //swagger content-type默认是application/json
                            newheaders.add("Content-Type: application/json");
                        }
                        para_bodystr += "\"" + _para_name + replaceStr("\": \"" + _para_format + "\",");
                    } else {
                        if (!isctset) {
                            isctset = true; //添加contenttype前将isctset设置为true
                            if (_para_format.contains("binary") || _para_format.contains("base64") || content_type.contains("form-data")) {
                                newheaders.add("Content-Type: multipart/form-data; boundary=" + boundary);
                                isupload = true;
                            } else
                                newheaders.add("Content-Type: " + content_type);
                        }
                        if (isupload) {
                            para_bodystr += "--" + boundary + newLine + String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"tmp.jpg\"", _para_name) + newLine + "Content-Type: " + content_type + newLine + newLine + "GIF89aaaaaaaaaaaaaaaaaaaa" + newLine;
                        } else if (content_type.contains("x-www-form-urlencoded"))
                            para_bodystr += String.format("&%s=%s", _para_name, replaceStr(_para_format));
                        else if (content_type.contains("json"))
                            para_bodystr += "\"" + _para_name + replaceStr("\": \"" + _para_format + "\",");
                        else if (content_type.contains("form-data")) {
                            para_bodystr += "--" + boundary + newLine + String.format("Content-Disposition: form-data; name=\"%s\";", _para_name) + newLine + newLine + replaceStr(_para_format) + newLine;
                        } else if (content_type.contains("xml")) ;

                    }
                    break;
                case "query":
                    para_querystr += String.format("&%s=%s", _para_name, replaceStr(_para_format));
                    break;
                case "formdata":
                case "form": // 兼容 1.x
                    if (!isctset) {
                        isctset = true; //swagger content-type默认是application/json
                        newheaders.add("Content-Type: multipart/form-data; boundary=" + boundary);
                    }
                    if (_para_format.toLowerCase().contains("file")) {
                        para_bodystr += "--" + boundary + newLine + String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"tmp.jpg\"", _para_name) + newLine + "Content-Type: application/octet-stream" + newLine + newLine + "GIF89aaaaaaaaaaaaaaaaaaaa" + newLine;
                    } else {
                        para_bodystr += "--" + boundary + newLine + String.format("Content-Disposition: form-data; name=\"%s\";", _para_name) + newLine + newLine + replaceStr(_para_format) + newLine;
                    }
                    break;
                case "header":
                    newheaders.add(_para_name + ": " + replaceStr(_para_format));
                    break;
                case "path":
                    path = path.replace("{" + _para_name + "}", replaceStr(_para_format));
                    break;

            }

        }
    }

    public void saveHttpRequest() {
        //生成query字符串
        if (para_querystr.startsWith("&")) {
            para_querystr = para_querystr.substring(1);
            para_querystr = "?" + para_querystr;
        }
        //生成body字符串
        if (para_bodystr.startsWith("&")) {
            para_bodystr = para_bodystr.substring(1);
        }
        //生成body json字符串
        if (para_bodystr.startsWith("\"")) {
            para_bodystr = "{" + para_bodystr.substring(0, para_bodystr.length() - 1) + "}";
        }
        //生成fromdata字符串
        if (para_bodystr.startsWith("-")) {
            para_bodystr += "--" + boundary + "--" + newLine;
        }

        //生成uri
        path += para_querystr;

        switch (method) {
            case "GET":
            case "PATCH":
            case "DELETE":
                break;
            case "POST":
//            case "PUT":    //避免开启探测之后出事 PUT DELETE不搞了
            default:
                newheaders.add("Content-Length: " + para_bodystr.length());
        }
        //设置请求方法和路径
        newheaders.set(0, method + " " + path + " HTTP/1.1");
//        try {
//
//            Iterator<String> iter = newheaders.iterator();
//            while (iter.hasNext()) {
//                String header = iter.next();
//                System.out.println(header);
//            }
//            System.out.println("\n" + para_bodystr + "\n");
//
//        } catch (Exception e) {
//            System.out.println(e.getMessage());
//        }
        apiRequestResponse.put(newheaders, para_bodystr.getBytes(StandardCharsets.UTF_8));
        newheaders = new ArrayList<>(headers);
    }


}

