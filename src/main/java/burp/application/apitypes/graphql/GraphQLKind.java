package burp.application.apitypes.graphql;

public enum GraphQLKind {
    OBJECT("OBJECT"),
    NON_NULL("NON_NULL"),
    INTERFACE("INTERFACE"),
    SCALAR("SCALAR"),
    ENUM("ENUM"),
    UNION("UNION"),
    LIST("LIST"),
    INPUT_OBJECT("INPUT_OBJECT"),

    INPUT_OBJECT_FIELD("INPUT_OBJECT_FIELD"),
    OBJECT_FIELD("OBJECT_FIELD"),
    OBJECT_FIELD_ARGUMENT("OBJECT_FIELD_ARGUMENT");


    String kind;

    private GraphQLKind(String kind) {
        this.kind = kind;
    }
}
