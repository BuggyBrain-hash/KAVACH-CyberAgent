import ast
import operator


OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos
}


def safe_eval(expression):

    tree = ast.parse(
        expression,
        mode="eval"
    )

    return evaluate_node(tree.body)


def evaluate_node(node):

    if isinstance(node, ast.Constant):

        if isinstance(
            node.value,
            (int, float)
        ):

            return node.value

        raise ValueError(
            "Only numbers are allowed."
        )

    if isinstance(node, ast.BinOp):

        operator_function = OPERATORS.get(
            type(node.op)
        )

        if operator_function is None:

            raise ValueError(
                "Operator not allowed."
            )

        left = evaluate_node(
            node.left
        )

        right = evaluate_node(
            node.right
        )

        return operator_function(
            left,
            right
        )

    if isinstance(node, ast.UnaryOp):

        operator_function = OPERATORS.get(
            type(node.op)
        )

        if operator_function is None:

            raise ValueError(
                "Unary operator not allowed."
            )

        operand = evaluate_node(
            node.operand
        )

        return operator_function(
            operand
        )

    raise ValueError(
        "Expression contains "
        "an unsupported operation."
    )