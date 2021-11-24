package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLUnion extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectType> possibleTypes = new ArrayList<>();

    public GraphQLUnion(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.UNION;

        for (JsonElement jsonElement : inputJson.getAsJsonArray("possibleTypes")) {
            this.possibleTypes.add(new GraphQLObjectType(jsonElement.getAsJsonObject()));
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        if (!super.enterExport(context)) {
            throw new GraphQLParseError("Recursion detected, this should not happened");
        }

        StringBuilder result = new StringBuilder();
        // 处理方式与 Interface 类似, 但是因为没有公共的属性, 所以删掉了子类找不到的情况

        result.append("{").append(Constants.GRAPHQL_NEW_LINE);
        for (GraphQLObjectType objectType : this.possibleTypes) {
            // 检测类是否存在 && 防止递归
            if (context.globalObjects.get(objectType.typeName) != null && !context.checkExportRecursion(objectType.typeName)) {
                result.append(context.getExportQueryIndent()).append("...").append(Constants.GRAPHQL_SPACE).append("on");
                result.append(Constants.GRAPHQL_SPACE).append(objectType.typeName).append(Constants.GRAPHQL_SPACE);
                result.append(context.globalObjects.get(objectType.typeName).exportToQuery(context));
                result.append(Constants.GRAPHQL_NEW_LINE);
            }
        }

        super.leaveExport(context);
        result.append(context.getExportQueryIndent()).append("}");

        return result.toString();
    }
}
