package burp.application.apitypes.graphql;

import java.util.HashMap;

public class GraphQLParseResult {
    public HashMap<String, String> queryParseResult = new HashMap<>();
    public HashMap<String, String> mutationParseResult = new HashMap<>();
}
