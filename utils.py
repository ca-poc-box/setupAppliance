from json import JSONEncoder
    
def byteify(input):
    if isinstance(input, dict):
        return dict((byteify(key),byteify(value)) for key,value in list(input.items()))
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, str):
        return input.encode('utf-8')
    else:
        return input
        
class ToJSON(JSONEncoder):
    def default(self, o):
        return getattr(o.__class__, "to_json", JSONEncoder().default)(o)
        #    return o.__json()
