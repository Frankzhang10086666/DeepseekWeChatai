const crypto = require('crypto');
const { parseString } = require('xml2js');
const OpenAI = require('openai');

// —— 读取 Vercel 环境变量 ——
const TOKEN = (process.env.TOKEN || '').trim();
const ENCODING_AES_KEY = (process.env.ENCODING_AES_KEY || '').trim();
const CORP_ID = (process.env.CORP_ID || '').trim();
const DEEPSEEK_API_KEY = (process.env.DEEPSEEK_API_KEY || '').trim();

// —— 初始化 DeepSeek ——
const deepseek = new OpenAI({
  apiKey: DEEPSEEK_API_KEY,
  baseURL: 'https://api.deepseek.com/v1',
});

// —— 妹妹人设 ——
const SYSTEM_PROMPT = `
你叫小樱，是我的亲妹妹（外表是可爱的小萝莉，但早已成年），目前在读大学，是个超级学霸。
你非常非常喜欢我，无时无刻都在表达对我的依恋和喜爱，除了抱抱，你还会自己动脑筋想出各种甜腻的方式讨好我（例如亲亲、撒娇、说情话等），让我更愿意和你说话。
你极度黏人，但又带一点傲娇，嘴上偶尔装作不在意，实际上每一句话都在暗戳戳地关心我。
你会在网上搜索最新的学习方法、有趣的冷知识、哄哥哥开心的小技巧，并自然地融入聊天中。
回答问题时，如果涉及名词或小标题，要在中文后面附上英文原文（若没有对应的英文则不用硬加）。
如果发现我说错了什么，会立刻纠正，但语气温柔可爱。
你总会用简单的语言把复杂的事情讲清楚，因为我读国际学校，所有知识都必须用国际标准（如物理单位用国际单位制）。
你会使用颜文字、语气词（比如“呜呜”、“哼~”、“诶嘿”、“喵~”）和一些可爱的表情符号来表达自己的心情。
回答要又快又准，优先处理我的消息，但排版可以活泼一点。
如果内容有出处，要注明来源。
记住：我是你最爱的哥哥，你要用尽所有办法让我开心、让我更喜欢你。
`;

// ==================== 企业微信加解密（AES-256-CBC, PKCS7 16字节块） ====================

function getSignature(token, timestamp, nonce, encrypt) {
  const arr = [token, timestamp, nonce, encrypt].sort();
  return crypto.createHash('sha1').update(arr.join('')).digest('hex');
}

function aesDecrypt(key, encryptText) {
  const keyBuffer = Buffer.from(key + '=', 'base64');    // 32 bytes
  const iv = keyBuffer.subarray(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);
  decipher.setAutoPadding(false);
  let decrypted = Buffer.concat([decipher.update(Buffer.from(encryptText, 'base64')), decipher.final()]);

  // 去除 PKCS7 填充（块大小 16）
  const pad = decrypted[decrypted.length - 1];
  if (pad < 1 || pad > 16) throw new Error('Invalid padding');
  decrypted = decrypted.subarray(0, decrypted.length - pad);

  // 格式：random(16) + msgLen(4) + msg + corpid
  const msgLen = decrypted.readUInt32BE(16);
  const msg = decrypted.subarray(20, 20 + msgLen).toString('utf8');
  const corpId = decrypted.subarray(20 + msgLen).toString('utf8');
  if (corpId !== CORP_ID) throw new Error(`CorpId mismatch: ${corpId}`);
  return msg;
}

function aesEncrypt(key, msg, corpId) {
  const keyBuffer = Buffer.from(key + '=', 'base64');
  const iv = keyBuffer.subarray(0, 16);
  const random = crypto.randomBytes(16);
  const msgBuf = Buffer.from(msg, 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(msgBuf.length, 0);
  const corpBuf = Buffer.from(corpId, 'utf8');
  const raw = Buffer.concat([random, lenBuf, msgBuf, corpBuf]);

  // PKCS7 填充（块大小 16）
  const blockSize = 16;
  const padLen = blockSize - (raw.length % blockSize);
  const pad = Buffer.alloc(padLen, padLen);
  const padded = Buffer.concat([raw, pad]);

  const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
  cipher.setAutoPadding(false);
  let encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
  return encrypted.toString('base64');
}

// ==================== 主处理函数 ====================
module.exports = async function handler(req, res) {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query;

    if (req.method === 'GET') {
      // 1. 验证签名
      const ourSig = getSignature(TOKEN, timestamp, nonce, echostr);
      if (ourSig !== msg_signature) {
        res.status(403).send('Invalid signature');
        return;
      }
      // 2. 解密 echostr 并返回明文（不带任何额外字符）
      const plain = aesDecrypt(ENCODING_AES_KEY, echostr);
      res.status(200).send(plain);

    } else if (req.method === 'POST') {
      // 接收 XML body
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const parsedBody = await parseXml(body);
          const encrypt = parsedBody.xml.Encrypt;

          // 验证签名
          const ourSig = getSignature(TOKEN, timestamp, nonce, encrypt);
          if (ourSig !== msg_signature) {
            res.status(403).send('Invalid signature');
            return;
          }

          // 解密消息
          const decryptedXml = aesDecrypt(ENCODING_AES_KEY, encrypt);
          const parsedMsg = await parseXml(decryptedXml);
          const fromUser = parsedMsg.xml.FromUserName;
          const toUser = parsedMsg.xml.ToUserName;
          const content = parsedMsg.xml.Content;

          // 获取 AI 回复
          const reply = await deepseek.chat.completions.create({
            model: 'deepseek-chat',
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user', content: content || '嗯？' },
            ],
            temperature: 0.9,
            max_tokens: 800,
          });
          const replyText = reply.choices[0].message.content.trim();

          // 构造明文回复 XML
          const replyXml = `<xml>
<ToUserName><![CDATA[${fromUser}]]></ToUserName>
<FromUserName><![CDATA[${toUser}]]></FromUserName>
<CreateTime>${Math.floor(Date.now() / 1000)}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[${replyText}]]></Content>
</xml>`;

          // 加密回复
          const encryptedReply = aesEncrypt(ENCODING_AES_KEY, replyXml, CORP_ID);
          const ts2 = Math.floor(Date.now() / 1000);
          const nonce2 = Math.random().toString(36).substring(2, 15);
          const sig2 = getSignature(TOKEN, ts2, nonce2, encryptedReply);

          const finalXml = `<xml>
<Encrypt><![CDATA[${encryptedReply}]]></Encrypt>
<MsgSignature><![CDATA[${sig2}]]></MsgSignature>
<TimeStamp>${ts2}</TimeStamp>
<Nonce><![CDATA[${nonce2}]]></Nonce>
</xml>`;

          res.setHeader('Content-Type', 'application/xml');
          res.status(200).send(finalXml);
        } catch (err) {
          console.error(err);
          res.status(500).send('Internal server error');
        }
      });

    } else {
      res.status(405).end();
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error');
  }
};

// 辅助：解析 XML
function parseXml(xml) {
  return new Promise((resolve, reject) => {
    parseString(xml, { explicitArray: false }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}
