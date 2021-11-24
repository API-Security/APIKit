package burp.application.apitypes.graphql;

import com.google.gson.JsonObject;

public abstract class GraphQLBaseObject {
    public String name;
    public String description;
    public GraphQLKind kind;

    public GraphQLBaseObject() {

    }

    public GraphQLBaseObject(JsonObject inputJson) {
        this.name = inputJson.getAsJsonPrimitive("name").getAsString();

        if (!inputJson.get("description").isJsonNull()) {
            this.description = inputJson.getAsJsonPrimitive("description").getAsString();
        }
    }

    public Boolean enterExport(GraphQLParseContext context) {
        // Object, Interface, Union 用得到, 解决对象的递归查询问题, 如果出现递归直接返回
        if (context.checkExportRecursion(this.name)) {
            return false;
        } else {
            context.exportToQueryStack.push(this.name);
            return true;
        }
    }

    public void leaveExport(GraphQLParseContext context) throws GraphQLParseError {
        // Object, Interface, Union 用得到
        String popName = context.exportToQueryStack.pop();
        if (!popName.equals(this.name)) {
            throw new GraphQLParseError("Stack unbalanced");
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        return "";
    }
}
