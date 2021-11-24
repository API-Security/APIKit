package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonObject;

public class GraphQLObjectFieldArgument extends GraphQLBaseObject {
    public GraphQLObjectType type;

    public GraphQLObjectFieldArgument(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.OBJECT_FIELD_ARGUMENT;

        this.type = new GraphQLObjectType(inputJson.getAsJsonObject("type"));
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        String result = "";
        result += this.name + ":" + Constants.GRAPHQL_SPACE;
        // 可能出现的有 Scalar, InputObject, Enum
        result += context.globalObjects.get(this.type.typeName).exportToQuery(context);
        return result;
    }
}
