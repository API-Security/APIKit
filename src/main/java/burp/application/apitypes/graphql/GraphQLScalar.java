package burp.application.apitypes.graphql;

import java.util.HashMap;

public class GraphQLScalar extends GraphQLBaseObject {
    public static HashMap<String, String> scalarDefaultValues = new HashMap<>();

    static {
        scalarDefaultValues.put("String", "\"string\"");
        scalarDefaultValues.put("Int", "1024");
        scalarDefaultValues.put("Float", "1.1");
        scalarDefaultValues.put("Boolean", "true");
        scalarDefaultValues.put("ID", "3");
    }

    String typeName;

    public GraphQLScalar(String typeName) {
        super();
        this.kind = GraphQLKind.SCALAR;
        this.typeName = typeName;
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        String result = "";
        if (scalarDefaultValues.containsKey(this.typeName)) {
            result = scalarDefaultValues.get(this.typeName);
        } else {
            // throw new GraphQLParseError("Unexpected scalar type " + this.typeName);
            result = String.format("\"undefined scalar type %s\"", this.typeName);
        }
        return result;
    }
}
