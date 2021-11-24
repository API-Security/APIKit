package burp.application.apitypes.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashMap;

public class GraphQLIntrospectionParser {
    GraphQLParseResult parseIntrospection(String introspectionJson) {
        JsonObject introspection = (JsonObject) JsonParser.parseString(introspectionJson);
        introspection = introspection.getAsJsonObject("data").getAsJsonObject("__schema");
        JsonArray types = introspection.getAsJsonArray("types");
        HashMap<String, GraphQLBaseObject> globalObjects = new HashMap<>();
        GraphQLParseContext context = new GraphQLParseContext(globalObjects);

        // 解析 GraphQL 自省得到的各种类/接口等等

        for (JsonElement element : types) {
            JsonObject object = element.getAsJsonObject();
            GraphQLKind objectKind = GraphQLKind.valueOf(object.getAsJsonPrimitive("kind").getAsString());
            String name = object.getAsJsonPrimitive("name").getAsString();

            switch (objectKind) {
                case OBJECT:
                    globalObjects.put(name, new GraphQLObject(object));
                    break;
                case INTERFACE:
                    globalObjects.put(name, new GraphQLInterface(object));
                    break;
                case SCALAR:
                    globalObjects.put(name, new GraphQLScalar(name));
                    break;
                case ENUM:
                    globalObjects.put(name, new GraphQLEnum(object));
                    break;
                case UNION:
                    globalObjects.put(name, new GraphQLUnion(object));
                    break;
                case INPUT_OBJECT:
                    globalObjects.put(name, new GraphQLInputObject(object));
                    break;
                default:
                    System.out.println(objectKind);
            }
        }

        GraphQLParseResult parseResult = new GraphQLParseResult();

        // 通过 QueryName, MutationName 得到实际的接口
        JsonElement queryTypeJson = introspection.get("queryType");
        if (!queryTypeJson.isJsonNull()) {
            String queryTypeName = queryTypeJson.getAsJsonObject().getAsJsonPrimitive("name").getAsString();
            GraphQLObject queryObject = (GraphQLObject) globalObjects.get(queryTypeName);
            for (GraphQLObjectField field : queryObject.fields) {
                try {
                    parseResult.queryParseResult.put(field.name, context.getExportQueryIndent() + field.exportToQuery(context));
                } catch (GraphQLParseError e) {
                    e.printStackTrace();
                }
            }
        }

        JsonElement mutationTypeJson = introspection.get("mutationType");
        if (!mutationTypeJson.isJsonNull()) {
            String mutationTypeName = mutationTypeJson.getAsJsonObject().getAsJsonPrimitive("name").getAsString();
            GraphQLObject mutationObject = (GraphQLObject) globalObjects.get(mutationTypeName);
            for (GraphQLObjectField field : mutationObject.fields) {
                try {
                    parseResult.mutationParseResult.put(field.name, context.getExportQueryIndent() + field.exportToQuery(context));
                } catch (GraphQLParseError e) {
                    e.printStackTrace();
                }
            }
        }

        return parseResult;
    }
}
