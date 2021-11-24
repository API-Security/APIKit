package burp.application.apitypes.graphql;

import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObjectType {
    public String typeName;
    public GraphQLKind kind;
    public ArrayList<GraphQLKind> modifiers = new ArrayList<>();

    public GraphQLObjectType(JsonObject jsonInput) {
        while (true) {
            GraphQLKind graphQLKind = GraphQLKind.valueOf(jsonInput.getAsJsonPrimitive("kind").getAsString());
            if (graphQLKind == GraphQLKind.NON_NULL || graphQLKind == GraphQLKind.LIST) {
                modifiers.add(graphQLKind);
            } else {
                this.kind = graphQLKind;
                break;
            }
            jsonInput = jsonInput.getAsJsonObject("ofType");
        }

        this.typeName = jsonInput.getAsJsonPrimitive("name").getAsString();
    }
}
