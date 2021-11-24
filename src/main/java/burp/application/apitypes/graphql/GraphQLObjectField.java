package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObjectField extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectFieldArgument> args = new ArrayList<>();
    public GraphQLObjectType type;

    public GraphQLObjectField(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.OBJECT_FIELD;

        for (JsonElement jsonElement : inputJson.getAsJsonArray("args")) {
            this.args.add(new GraphQLObjectFieldArgument(jsonElement.getAsJsonObject()));
        }

        this.type = new GraphQLObjectType(inputJson.getAsJsonObject("type"));
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        StringBuilder result = new StringBuilder();

        result.append(this.name).append(Constants.GRAPHQL_SPACE);

        if (this.args.size() > 0) {
            result.append("(");
            for (int i = 0; i < args.size(); i++) {
                GraphQLObjectFieldArgument arg = args.get(i);
                result.append(arg.exportToQuery(context));
                if (i != args.size() - 1) {
                    result.append(",").append(Constants.GRAPHQL_SPACE);
                }
            }
            result.append(")").append(Constants.GRAPHQL_SPACE);
        }

        switch (this.type.kind) { // 如果 Field 的 type 是个对象, 继续查询这个对象
            case UNION:
            case OBJECT:
            case INTERFACE:
                if (context.checkExportRecursion(this.type.typeName)) {
                    return ""; // 检查到递归查询, 直接返回空字符串
                } else {
                    result.append(context.globalObjects.get(this.type.typeName).exportToQuery(context));
                }
        }
        return result.toString();
    }
}
