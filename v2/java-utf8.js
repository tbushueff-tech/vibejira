// Java UTF-8 encoding replaces unpaired UTF-16 surrogates with '?'.
// TextEncoder alone uses U+FFFD, which changes the signed bytes.
export function javaUtf8(value) {
  let text = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) text += value[i] + value[++i];
      else text += "?";
    } else text += code >= 0xdc00 && code <= 0xdfff ? "?" : value[i];
  }
  return new TextEncoder().encode(text);
}
