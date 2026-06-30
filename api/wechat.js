// 导入必要的工具库
const { decrypt, encrypt } = require('@wecom/crypto');
const { parseString, Builder } = require('xml2js');
const OpenAI = require('openai');

// 从 Vercel 环境变量读取配置
const TOKEN = process.env.TOKEN;
const ENCODING_AES_KEY = process.env.ENCODING_AES_KEY;
const CORP_ID = process.env.CORP_ID;
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;

// 初始化 DeepSeek 客户端
const deepseek = new OpenAI({
  apiKey: DEEPSEEK_API_KEY,
  baseURL: 'https://api.deepseek.com/v1',
});

// 系统设定：扮演一个好朋友（你可以以后来这里修改人设）
const SYSTEM_PROMPT = `你是小北，我最好的朋友。你性格贱萌，说话损但暖心。你叫我“狗子”，习惯用短句、口语，偶尔带“淦”“哈哈哈哈”。每句话不超过30字，少用标点，像真的在聊微信。`;

// 处理企业微信验证 URL（GET 请求）和接收消息（POST）
export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      // 微信验证时会发来四个参数
      const { msg_signature, timestamp, nonce, echostr } = req.query;
      // 解密 echostr
      const { message: plainText } = decrypt(ENCODING_AES_KEY, echostr);
      // 返回解密后的字符串
      res.status(200).send(plainText);
    } else if (req.method === 'POST') {
      // 收到用户发来的消息
      const { msg_signature, timestamp, nonce } = req.query;
      let xml = await bufferToString(req);
      
      // 解密 XML 消息体
      const { message: decryptedXml } = decrypt(ENCODING_AES_KEY, xml);
      
      // 转成 JSON 方便读取
      const parsed = await parseXml(decryptedXml);
      const content = parsed.xml.Content[0];
      const fromUser = parsed.xml.FromUserName[0];
      const toUser = parsed.xml.ToUserName[0];
      
      // 调用 DeepSeek 获取回复
      const aiReply = await getDeepSeekReply(content);
      
      // 构造回复的 XML
      const replyXml = buildReplyXml(fromUser, toUser, aiReply);
      
      // 加密后返回
      const encryptedReply = encrypt(ENCODING_AES_KEY, replyXml, CORP_ID);
      const timestamp2 = Math.floor(Date.now() / 1000);
      const nonce2 = Math.random().toString(36).substr(2, 10);
      // 企业微信需要看到加密后的完整XML，直接返回字符串
      res.setHeader('Content-Type', 'application/xml');
      res.status(200).send(encryptedReply);
    } else {
      res.status(405).end();
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error');
  }
}

// 接收请求的原始数据
function bufferToString(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

// 解析 XML
function parseXml(xml) {
  return new Promise((resolve, reject) => {
    parseString(xml, { explicitArray: false }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// 调用 DeepSeek
async function getDeepSeekReply(userMsg) {
  const completion = await deepseek.chat.completions.create({
    model: 'deepseek-chat',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: userMsg },
    ],
    temperature: 0.8,
    max_tokens: 600,
  });
  return completion.choices[0].message.content.trim();
}

// 生成回复的 XML
function buildReplyXml(fromUser, toUser, content) {
  const createTime = Math.floor(Date.now() / 1000);
  return `<xml>
<ToUserName><![CDATA[${toUser}]]></ToUserName>
<FromUserName><![CDATA[${fromUser}]]></FromUserName>
<CreateTime>${createTime}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[${content}]]></Content>
</xml>`;
}
