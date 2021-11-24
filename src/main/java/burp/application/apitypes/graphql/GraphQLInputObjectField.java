package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonObject;

public class GraphQLInputObjectField extends GraphQLBaseObject {
    public GraphQLObjectType type;

    public GraphQLInputObjectField(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.INPUT_OBJECT_FIELD;

        this.type = new GraphQLObjectType(inputJson.getAsJsonObject("type"));
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        String result = this.name + ":" + Constants.GRAPHQL_SPACE;
        result += context.globalObjects.get(this.type.typeName).exportToQuery(context);
        return result;
    }
}
