package burp.application.apitypes.graphql;

import burp.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLInputObject extends GraphQLBaseObject {
    public ArrayList<GraphQLInputObjectField> inputFields = new ArrayList<>();

    public GraphQLInputObject(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.INPUT_OBJECT;

        for (JsonElement jsonElement : inputJson.getAsJsonArray("inputFields")) {
            this.inputFields.add(new GraphQLInputObjectField(jsonElement.getAsJsonObject()));
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        StringBuilder result = new StringBuilder("{").append(Constants.GRAPHQL_SPACE);
        for (int i = 0; i < this.inputFields.size(); i++) {
            GraphQLInputObjectField inputObjectField = this.inputFields.get(i);
            result.append(inputObjectField.exportToQuery(context));
            if (i != this.inputFields.size() - 1) {
                result.append(",").append(Constants.GRAPHQL_SPACE);
            }
        }
        result.append(Constants.GRAPHQL_SPACE).append("}");
        return result.toString();
    }
}
