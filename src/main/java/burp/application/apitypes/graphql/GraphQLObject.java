package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObject extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectField> fields = new ArrayList<>();

    public GraphQLObject(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.OBJECT;

        for (JsonElement jsonElement : inputJson.getAsJsonArray("fields")) {
            this.fields.add(new GraphQLObjectField(jsonElement.getAsJsonObject()));
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        if (!super.enterExport(context)) {
            throw new GraphQLParseError("Recursion detected, this should not happened");
        }

        StringBuilder result = new StringBuilder("{" + Constants.GRAPHQL_NEW_LINE);
        for (GraphQLObjectField field : this.fields) {
            result.append(context.getExportQueryIndent()).append(field.exportToQuery(context));
            result.append(Constants.GRAPHQL_NEW_LINE);
        }
        super.leaveExport(context);
        result.append(context.getExportQueryIndent()).append("}");
        return result.toString();
    }
}
