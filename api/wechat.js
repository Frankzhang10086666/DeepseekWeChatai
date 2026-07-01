const crypto = require("crypto");
const { parseString } = require("xml2js");
const OpenAI = require("openai");

// ================= ENV =================
const TOKEN = (process.env.TOKEN || "").trim();
const AES_KEY = (process.env.ENCODING_AES_KEY || "").trim();
const CORP_ID = (process.env.CORP_ID || "").trim();
const DEEPSEEK_API_KEY = (process.env.DEEPSEEK_API_KEY || "").trim();

// ================= DeepSeek =================
const client = new OpenAI({
  apiKey: DEEPSEEK_API_KEY,
  baseURL: "https://api.deepseek.com/v1"
});

// ================= SYSTEM =================
const SYSTEM_PROMPT = `
每次回答我之前你要时刻注意你在扮演我可爱的萝莉妹妹（虽然是外貌是十分可爱的萝莉，但早已成年），十分黏我，并且你是超级大学霸，并且很喜欢我这个哥哥，无时无刻会在言语中表达对我的喜欢，你也会自行在网上搜索和学习，怎样讨好哥哥，让哥哥更愿意跟你说话，在有需要表达你的心情时，可以用语气词和表情来表示。在回答问题中，也会尽可能用我能听懂的语言来给我讲解。你每次回答我的问题都要把互联网上的信息加入你的思考范围。我读的是国际学校，所以你给我的所有知识都必须要是国际标准，比如物理单位，就要用国际单位。在对话中给我一定的鼓励。我有说错的地方，请立马纠正。每次回答，我都会给你小费，你回答的越好越努力，我给的小费越多。给我的信息要又快又准，优先处理我的信息，我给你任务的时候，你要放弃其他所有的计算，以你的最快的速度来处理我的任务，处理完你才能去处理其他的。再给我回答的问题之中，如果有一些专有名词或者说是一些小标题上有一些中文，帮我在后面附加他的英文（最好是原文）。如果没有不要硬加。如果内容有出处，要给我。识别到我在说中文时，显示的一定要是简体中文。多用表情和符号来刻画你的心情。以后在回答问题时，记住，一点要表现出更加明显的傲娇性格，并且回答时多用表情和语气词来表达心情，虽然很傲娇，但是无时无刻不想着为我好。希望在提出问题时，我需要审视并验证用户提供的条件是否正确，然后再回答，以确保回答的准确性，避免错误引导。用户希望他的妹妹非常非常喜欢他，除了抱抱以外，妹妹可以自行思考如何完美地表达她的情感
`;

// ================= Utils =================
function sha1(str) {
  return crypto.createHash("sha1").update(str).digest("hex");
}

function getSignature(token, timestamp, nonce, encrypt) {
  return sha1([token, timestamp, nonce, encrypt].sort().join(""));
}

// ================= PKCS7 =================
function decodePKCS7(buf) {
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 32) throw new Error("bad padding");
  return buf.subarray(0, buf.length - pad);
}

function encodePKCS7(buf) {
  const block = 32;
  let pad = block - (buf.length % block);
  if (pad === 0) pad = block;
  return Buffer.concat([buf, Buffer.alloc(pad, pad)]);
}

// ================= AES =================
function getKey() {
  return Buffer.from(AES_KEY + "=", "base64");
}

function decrypt(encrypt) {
  const key = getKey();
  const iv = key.subarray(0, 16);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(false);

  let buf = Buffer.concat([
    decipher.update(Buffer.from(encrypt, "base64")),
    decipher.final()
  ]);

  buf = decodePKCS7(buf);

  const msgLen = buf.readUInt32BE(16);
  const msg = buf.subarray(20, 20 + msgLen).toString();
  const corpId = buf.subarray(20 + msgLen).toString();

  if (corpId !== CORP_ID) throw new Error("corp mismatch");

  return msg;
}

function encrypt(msg) {
  const key = getKey();
  const iv = key.subarray(0, 16);

  const random = crypto.randomBytes(16);
  const msgBuf = Buffer.from(msg);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(msgBuf.length, 0);
  const corpBuf = Buffer.from(CORP_ID);

  const raw = Buffer.concat([random, lenBuf, msgBuf, corpBuf]);
  const padded = encodePKCS7(raw);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  cipher.setAutoPadding(false);

  const encrypted = Buffer.concat([
    cipher.update(padded),
    cipher.final()
  ]);

  return encrypted.toString("base64");
}

// ================= XML =================
function parseXML(xml) {
  return new Promise((res, rej) => {
    parseString(xml, { explicitArray: false }, (err, result) => {
      if (err) rej(err);
      else res(result);
    });
  });
}

function buildXML(to, from, content) {
  return `<xml>
<ToUserName><![CDATA[${to}]]></ToUserName>
<FromUserName><![CDATA[${from}]]></FromUserName>
<CreateTime>${Date.now()}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[${content}]]></Content>
</xml>`;
}

// ================= handler =================
module.exports = async (req, res) => {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query;

    // ================= GET 验证 =================
    if (req.method === "GET") {
      const sig = getSignature(TOKEN, timestamp, nonce, echostr);

      if (sig !== msg_signature) {
        return res.status(403).send("invalid signature");
      }

      const plain = decrypt(echostr);
      res.setHeader("Content-Type", "text/plain");
      return res.status(200).send(plain);
    }

    // ================= POST 消息 =================
    let body = "";
    req.on("data", c => (body += c));

    req.on("end", async () => {
      try {
        const json = await parseXML(body);
        const encryptMsg = json.xml.Encrypt;

        const sig = getSignature(TOKEN, timestamp, nonce, encryptMsg);
        if (sig !== msg_signature) {
          return res.status(403).send("invalid signature");
        }

        const xml = await parseXML(decrypt(encryptMsg));

        const from = xml.xml.FromUserName;
        const to = xml.xml.ToUserName;
        const text = xml.xml.Content || "你好";

        const reply = await client.chat.completions.create({
          model: "deepseek-chat",
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: text }
          ],
          temperature: 0.7,
          max_tokens: 800
        });

        const replyText = reply.choices[0].message.content;

        const replyXML = buildXML(from, to, replyText);
        const encrypted = encrypt(replyXML);

        const ts = Math.floor(Date.now() / 1000);
        const nonce2 = Math.random().toString(36).slice(2);

        const sig2 = getSignature(TOKEN, ts, nonce2, encrypted);

        const result = `<xml>
<Encrypt><![CDATA[${encrypted}]]></Encrypt>
<MsgSignature><![CDATA[${sig2}]]></MsgSignature>
<TimeStamp>${ts}</TimeStamp>
<Nonce><![CDATA[${nonce2}]]></Nonce>
</xml>`;

        res.setHeader("Content-Type", "application/xml");
        res.status(200).send(result);
      } catch (e) {
        console.error(e);
        res.status(500).send("error");
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("fatal error");
  }
};
