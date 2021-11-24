package burp.application.apitypes.graphql;

import burp.utils.CommonUtils;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.HashMap;

public class GraphQLEnum extends GraphQLBaseObject {
    public HashMap<String, String> enumValues = new HashMap<>(); // {name: description}

    public GraphQLEnum(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.ENUM;

        for (JsonElement jsonElement : inputJson.getAsJsonArray("enumValues")) {
            JsonObject enumObject = jsonElement.getAsJsonObject();

            String enumName = enumObject.getAsJsonPrimitive("name").getAsString();
            String enumDescription = null;

            if (!enumObject.get("description").isJsonNull()) {
                enumDescription = enumObject.getAsJsonPrimitive("description").getAsString();
            }
            this.enumValues.put(enumName, enumDescription);
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        return CommonUtils.randomChoice(this.enumValues.keySet());
    }
}
