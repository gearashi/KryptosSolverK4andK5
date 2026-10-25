"""Independent literal replay for per-stage alphabets and expanded phase keys."""
import hashlib
import string


def replay_expanded(plaintext,recipe):
    if not isinstance(recipe,dict) or recipe.get("schema")!="kryptos.expanded-recipe.v1":
        raise ValueError("unsupported expanded recipe")
    if not isinstance(plaintext,str) or not 1<=len(plaintext)<=4096 or any(c not in string.ascii_uppercase for c in plaintext):
        raise ValueError("a complete uppercase plaintext is required")
    stages=recipe.get("stages")
    if not isinstance(stages,list) or not 1<=len(stages)<=16:
        raise ValueError("recipe needs1..16stages")
    text=plaintext
    trace=[]
    for number,stage in enumerate(stages,1):
        if not isinstance(stage,dict):
            raise ValueError("invalid stage")
        if stage.get("operation")=="gather":
            route=stage.get("permutation")
            if not isinstance(route,list) or len(route)!=len(text) or any(type(i) is not int for i in route) or sorted(route)!=list(range(len(text))):
                raise ValueError("gather must be bijective")
            text="".join(text[i] for i in route)
        elif stage.get("operation")=="repeat_substitution":
            alphabet=stage.get("alphabet")
            key=stage.get("key_pattern")
            rule=stage.get("cipher")
            if not isinstance(alphabet,str) or len(alphabet)!=26 or set(alphabet)!=set(string.ascii_uppercase):
                raise ValueError("each substitution needs its explicit alphabet")
            if not isinstance(key,str) or len(key)!=len(text) or any(c not in alphabet for c in key):
                raise ValueError("an expanded key must cover each message position")
            if rule not in ("vigenere","beaufort","variant"):
                raise ValueError("unsupported substitution")
            output=[]
            for c,k in zip(text,key):
                p=alphabet.index(c)
                v=alphabet.index(k)
                output.append(alphabet[(p+v if rule=="vigenere" else v-p if rule=="beaufort" else p-v)%26])
            text="".join(output)
        else:
            raise ValueError("unsupported operation")
        trace.append({"stage":number,"operation":stage["operation"],"output":text,"sha256":hashlib.sha256(text.encode()).hexdigest()})
    return {"ciphertext":text,"stages":trace}
