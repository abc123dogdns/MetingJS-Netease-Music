import { connect } from "cloudflare:sockets";

// -------------------------主入口判断部分-------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    //可在：域名/encode?text=ts.hpc.tw:443&pwd=sdpoi988asdgasdreler789qweriuysaqljk2648qijoi 这样的方式获得加密反代再放在客户端路径
    if (url.pathname === "/encode") {
      // 获取明文和密码参数
      const text = url.searchParams.get("text") || "";
      const pwd = url.searchParams.get("pwd") || "sdpoi988asdgasdreler789qweriuysaqljk2648qijoi";

      // 简单输入验证
      if (!text) {
        return new Response("请提供 text 参数", { status: 400 });
      }

      // 调用加密函数
      const encrypted = 加密反代IP(text, pwd);

      return new Response(encrypted, {
        status: 200,
        headers: { "Content-Type": "text/plain;charset=utf-8" }
      });
    }

    // 你的原始逻辑，判断 WebSocket 还是普通请求
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      return await handleVP(request);
    }

    return await env.ASSETS.fetch(request); // 项目静态网页
  }
};




// -------------------------VP 部分-------------------------
async function handleVP(request) {

  let 哎呀呀这是我的VL密钥 = "d342d11e-d424-4583-b36e-524ab1f0afa4"; //这是真实的UUID，通用订阅会进行验证，建议修改为自己的规范化UUID
  let 启用反代功能 = true //选择是否启用反代功能【总开关】，false，true，现在你可以自由的选择是否启用反代功能了
  let 反代IP = '72.13.122.137' //反代IP或域名，反代IP端口一般情况下不用填写，如果你非要用非标反代的话，可以填'ts.hpc.tw:443'这样

  const url = new URL(request.url);


  // 先从查询参数获取 proxyip    例如：/?proxyip=your_value:port , proxyip可改具体见代码
  const queryParams = new URLSearchParams(url.search);
  let 最终反代IP = queryParams.get("class");

  // 如果没参数，则尝试从路径中提取  例如: /proxyip/1.2.3.4:443或加密形式/proxyip/ABwBGgYYAw , proxyip可改具体见代码
  if (!最终反代IP) {
    const match = url.pathname.match(/^\/class\/([^\/]+)(\/|$)/i);
  if (match) {
    try {
      最终反代IP = 解密反代IP(match[1]);
    } catch (e) {
      最终反代IP = match[1];
    }
   }
  }

  console.log("最终反代IP:", 最终反代IP);
  反代IP = 最终反代IP || "72.13.122.137";




  return await 升级WS请求(request, 哎呀呀这是我的VL密钥, 启用反代功能, 反代IP);
}

function 加密反代IP(明文, 密码 = "sdpoi988asdgasdreler789qweriuysaqljk2648qijoi") {
  const pwd = Array.from(密码).map(c => c.charCodeAt(0));
  const bytes = Array.from(明文).map((c, i) => c.charCodeAt(0) ^ pwd[i % pwd.length]);
  const encoded = btoa(String.fromCharCode(...bytes));
  // URL安全 base64 替换
  return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function 解密反代IP(str, 密码 = "sdpoi988asdgasdreler789qweriuysaqljk2648qijoi") {
  str = str.replace(/-/g, '+').replace(/_/g, '/');  // URL safe反转
  const bytes = atob(str).split("").map(c => c.charCodeAt(0));
  const pwd = Array.from(密码).map(c => c.charCodeAt(0));
  return bytes.map((b, i) => b ^ pwd[i % pwd.length]).map(c => String.fromCharCode(c)).join("");
}



// -------------------------VP 部分核心函数-------------------------
async function 升级WS请求(访问请求, VL密钥, 反代开关, 反代IP) {
  const [客户端, WS接口] = new WebSocketPair(); //创建WS接口对象
  const 读取我的加密访问内容数据头 = 访问请求.headers.get('sec-websocket-protocol'); //读取访问标头中的WS通信数据
  const 解密数据 = 使用64位加解密(读取我的加密访问内容数据头); //解密目标访问数据，传递给TCP握手进程
  await 解析VL标头(解密数据, WS接口, VL密钥, 反代开关, 反代IP); //解析VL数据并进行TCP握手
  return new Response(null, { status: 101, webSocket: 客户端 }); //一切准备就绪后，回复客户端WS连接升级成功
}

function 使用64位加解密(还原混淆字符) {
  还原混淆字符 = 还原混淆字符.replace(/-/g, '+').replace(/_/g, '/');
  const 解密数据 = atob(还原混淆字符);
  const 解密_你_个_丁咚_咙_咚呛 = Uint8Array.from(解密数据, (c) => c.charCodeAt(0));
  return 解密_你_个_丁咚_咙_咚呛.buffer;
}

// 第二步，解读VL协议数据，创建TCP握手
async function 解析VL标头(VL数据, WS接口, VL密钥, 反代开关, 反代IP, TCP接口) {
  if (验证VL的密钥(new Uint8Array(VL数据.slice(1, 17))) !== VL密钥) {
    return null;
  }
  const 获取数据定位 = new Uint8Array(VL数据)[17];
  const 提取端口索引 = 18 + 获取数据定位 + 1;
  const 建立端口缓存 = VL数据.slice(提取端口索引, 提取端口索引 + 2);
  const 访问端口 = new DataView(建立端口缓存).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  const 建立地址缓存 = new Uint8Array(VL数据.slice(提取地址索引, 提取地址索引 + 1));
  const 识别地址类型 = 建立地址缓存[0];
  let 地址长度 = 0;
  let 访问地址 = '';
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度)).join('.');
      break;
    case 2:
      地址长度 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 1))[0];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const dataView = new DataView(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); }
      访问地址 = ipv6.join(':');
      break;
  }
  const 写入初始数据 = VL数据.slice(地址信息索引 + 地址长度);
  try {
    TCP接口 = connect({ hostname: 访问地址, port: 访问端口 });
    await TCP接口.opened;
  } catch {
    if (反代开关 && 反代IP) {
      let [反代IP地址, 反代IP端口] = 反代IP.split(':');
      TCP接口 = connect({ hostname: 反代IP地址, port: 反代IP端口 || 访问端口 });
    } else {
      throw new Error('TCP连接失败，且反代未开启或无反代IP');
    }
  }
  建立传输管道(WS接口, TCP接口, 写入初始数据);
}

function 验证VL的密钥(arr, offset = 0) {
  const uuid = (转换密钥格式[arr[offset + 0]] + 转换密钥格式[arr[offset + 1]] + 转换密钥格式[arr[offset + 2]] + 转换密钥格式[arr[offset + 3]] + "-" +
    转换密钥格式[arr[offset + 4]] + 转换密钥格式[arr[offset + 5]] + "-" +
    转换密钥格式[arr[offset + 6]] + 转换密钥格式[arr[offset + 7]] + "-" +
    转换密钥格式[arr[offset + 8]] + 转换密钥格式[arr[offset + 9]] + "-" +
    转换密钥格式[arr[offset + 10]] + 转换密钥格式[arr[offset + 11]] + 转换密钥格式[arr[offset + 12]] + 转换密钥格式[arr[offset + 13]] + 转换密钥格式[arr[offset + 14]] + 转换密钥格式[arr[offset + 15]]
  ).toLowerCase();
  return uuid;
}
const 转换密钥格式 = [];
for (let i = 0; i < 256; ++i) { 转换密钥格式.push((i + 256).toString(16).slice(1)); }

// 第三步，创建客户端WS-CF-目标的传输通道并监听状态
async function 建立传输管道(WS接口, TCP接口, 写入初始数据) {
  WS接口.accept(); //打开WS接口连接通道
  WS接口.send(new Uint8Array([0, 0]).buffer); //向客户端发送WS接口初始化消息
  const 传输数据 = TCP接口.writable.getWriter(); //打开TCP接口写入通道
  const 读取数据 = TCP接口.readable.getReader(); //打开TCP接口读取通道
  if (写入初始数据) await 传输数据.write(写入初始数据); //向TCP接口推送标头中提取的初始访问数据
  WS接口.addEventListener('message', event => { 传输数据.write(event.data) }); //监听客户端WS接口后续数据，推送给TCP接口
  while (true) {
    let 返回数据 = (await 读取数据.read()).value;
    if (返回数据) {
      WS接口.send(返回数据);
    } else {
      break;
    }
  }
}
