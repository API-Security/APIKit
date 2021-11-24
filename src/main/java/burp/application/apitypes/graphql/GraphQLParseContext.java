package burp.application.apitypes.graphql;

import burp.utils.Constants;

import java.util.Collections;
import java.util.HashMap;
import java.util.Stack;

public class GraphQLParseContext {
    HashMap<String, GraphQLBaseObject> globalObjects;
    Stack<String> exportToQueryStack = new Stack<>();

    public GraphQLParseContext(HashMap<String, GraphQLBaseObject> globalObjects) {
        this.globalObjects = globalObjects;
    }

    public String getExportQueryIndent() {
        return String.join("", Collections.nCopies(exportToQueryStack.size() + 1, Constants.GRAPHQL_TAB)); // 这里用 exportToQueryStack.size() + 1 的原因是外层有一个 query / mutation 包裹, 所以额外缩进一层
    }

    public Boolean checkExportRecursion(String name) {
        // 不允许自己出现
        return Collections.frequency(this.exportToQueryStack, name) > 0;
    }
}
