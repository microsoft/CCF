export function compute(request) {
    const body = request.body.json();

    if (typeof body.left != 'number' || typeof body.right != 'number') {
        return {
            statusCode: 400,
            body: {
                error: 'invalid operand type'
            }
        }
    }

    let result;
    if (body.op == 'add')
        result = body.left + body.right;
    else if (body.op == 'sub')
        result = body.left - body.right;
    else if (body.op == 'mul')
        result = body.left * body.right;
    else {
        return {
            statusCode: 400,
            body: {
                error: 'unknown op'
            }
        }
    }
    
    return {
        body: {
            result: result
        }
    }
}
