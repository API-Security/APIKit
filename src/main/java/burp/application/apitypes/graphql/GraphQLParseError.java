package burp.application.apitypes.graphql;

public class GraphQLParseError extends Exception {
    public GraphQLParseError(String msg) {
        super(msg);
    }
}
