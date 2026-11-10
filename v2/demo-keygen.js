import { readDemoDsaPrivateKey } from "./demo-private-key.js";

// Чтение вашего обновленного оригинального приватного ключа
const { rawPrivateKeyString } = readDemoDsaPrivateKey();
const encoder = new TextEncoder();

/**
 * Имитация порядка итерации стандартного Java HashMap для Atlassian.
 * Порядок полей в оригинальном HashMap жестко фиксирован для данного набора ключей.
 */
function alignFieldsAsJavaHashMap(properties, productNamespace) {
  const javaHashMapOrder = [
    'Description',
    'NumberOfUsers',
    'CreationDate',
    'Evaluation',
    `${productNamespace}.NumberOfUsers`,
    'XMPPServiceKey',
    'ContactEMail',
    `${productNamespace}.productKey`,
    'MaintenanceExpiryDate',
    'Organisation',
    'jira.LicenseEdition',
    'LicenseExpiryDate',
    'keyVersion',
    'LicenseTypeName',
    'PurchaseDate',
    'PartnerName',
    'ServerId',
    'Subscription'
  ];

  const orderedProperties = {};
  for (const key of javaHashMapOrder) {
    if (properties[key] !== undefined) {
      orderedProperties[key] = properties[key];
    }
  }
  // Дозапись плагинов, если они есть
  for (const key of Object.keys(properties)) {
    if (orderedProperties[key] === undefined) {
      orderedProperties[key] = properties[key];
    }
  }
  return orderedProperties;
}

/**
 * Форматирование даты в локальном времени машины (аналог java.util.Date)
 */
function formatAsJavaLocalPlainDate(date) {
  const offset = date.getTimezoneOffset();
  const localDate = new Date(date.getTime() - (offset * 60 * 1000));
  return localDate.toISOString().split('T')[0];
}

function concat(...arrays) {
  const result = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const part of arrays) { result.set(part, offset); offset += part.length; }
  return result;
}

function base64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(text);
}

function formatBase31(num) {
  if (!num) return "0";
  const digits = "0123456789abcdefghijklmnopqrstu";
  let output = "";
  for (; num > 0; num = Math.floor(num / 31)) output = digits[num % 31] + output;
  return output;
}

async function zlibCompress(bytes) {
  if (typeof CompressionStream !== "function")
    throw new Error("Браузер не поддерживает CompressionStream (deflate)");
  const source = new Blob([bytes]).stream();
  const stream = source.pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Нативная подпись через Web Crypto API с использованием вашего PRIVATE_KEY_STR
 */
async function nativeAgentSign(messageBuffer) {
  // Импортируем оригинальный приватный ключ (предварительно очищенный от заголовков PEM)
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = rawPrivateKeyString
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s+/g, "");
  
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "NODE-DSA", // Или "DSA" / "RSASSA-PKCS1-v1_5" в зависимости от типа вашего импортированного ключа
      hash: { name: "SHA-1" },
    },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    { name: "NODE-DSA" },
    privateKey,
    messageBuffer
  );
  
  return new Uint8Array(sig);
}

/**
 * Сборка текстового блока свойств как в оригинальном Atlassian-Agent
 */
export async function buildJiraPropertiesText(fields) {
  const { serverId, organisation, email, productNamespace, expiryDate } = fields;
  const now = new Date();
  const exp = new Date(expiryDate);

  const rawProperties = {
    'Description': `License for ${organisation}`, // Оригинальный динамический текст
    'ServerId': serverId,
    'Organisation': organisation,
    'ContactEMail': email,
    'CreationDate': formatAsJavaLocalPlainDate(now),
    'PurchaseDate': formatAsJavaLocalPlainDate(now),
    'LicenseExpiryDate': formatAsJavaLocalPlainDate(exp),
    'MaintenanceExpiryDate': formatAsJavaLocalPlainDate(exp),
    'NumberOfUsers': '-1',
    'Evaluation': 'false',
    'LicenseTypeName': 'COMMERCIAL',
    'keyVersion': '1600708331'
  };

  rawProperties[`${productNamespace}.NumberOfUsers`] = '-1';
  rawProperties[`${productNamespace}.productKey`] = productNamespace;

  // Сортируем по бакетам HashMap Java
  const ordered = alignFieldsAsJavaHashMap(rawProperties, productNamespace);

  let textBlock = "";
  for (const [key, value] of Object.entries(ordered)) {
    const escapedKey = key.replace(/([:= \t\r\n\f])/g, '\\$1');
    const escapedValue = value.replace(/([:=])/g, '\\$1');
    textBlock += `${escapedKey}=${escapedValue}\n`;
  }

  // Внутренняя подпись licenseHash
  const textBytes = encoder.encode(textBlock);
  const internalSig = await nativeAgentSign(textBytes);
  const internalSigBase64 = base64(internalSig);

  textBlock += `licenseHash=${internalSigBase64}\n`;
  return textBlock;
}

/**
 * Основной метод генерации финального ключа
 */
export async function generateJiraDemoKey(fields) {
  // 1. Генерируем тестовый блок свойств с внутренней подписью
  const propertiesText = await buildJiraPropertiesText(fields);
  
  // 2. Сжатие zlib Deflate
  const compressed = await zlibCompress(encoder.encode(propertiesText));
  
  // 3. Добавление префикса 0D 0E 0C 0A 0F
  const payload = concat(Uint8Array.of(13, 14, 12, 10, 15), compressed);
  
  // 4. Внешняя подпись поверх всего бинарного блока
  const outerSignature = await nativeAgentSign(payload);
  
  // 5. Запись длины подписи в 2 байта (Big Endian) как делает оригинальный jar-конвертер
  const sigLengthBuffer = new Uint8Array(2);
  new DataView(sigLengthBuffer.buffer).setUint16(0, outerSignature.length, false);

  // 6. Сборка финального бинарного пакета
  const finalBinaryLicense = concat(payload, sigLengthBuffer, outerSignature);
  
  // 7. Base64 и суффикс длины системы счисления 31
  const encoded = base64(finalBinaryLicense);
  const full = encoded + "X02" + formatBase31(encoded.length);
  
  // Форматирование по 76 символов в строку (стандарт упаковки Atlassian)
  const result = [...full].map((char, i) => char + (i > 0 && i % 76 === 0 ? "\n" : "")).join("");
  
  return { 
    key: result, 
    properties: propertiesText, 
    format: "Atlassian Agent Production License" 
  };
}
