"""
Minimal test handler to diagnose Vercel Python issues
"""
def handler(request):
    try:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'body': f'Test handler works! Request type: {type(request)}'
        }
    except Exception as e:
        import traceback
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': f'Error: {str(e)}\n{traceback.format_exc()}'
        }

