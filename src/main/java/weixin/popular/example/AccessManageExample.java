package weixin.popular.example;

import com.qq.weixin.mp.aes.AesException;
import com.qq.weixin.mp.aes.WXBizMsgCrypt;
import weixin.popular.api.ComponentAPI;
import weixin.popular.api.MessageAPI;
import weixin.popular.bean.component.AuthorizerAccessToken;
import weixin.popular.bean.component.ComponentAccessToken;
import weixin.popular.bean.component.ComponentReceiveXML;
import weixin.popular.bean.component.PreAuthCode;
import weixin.popular.bean.message.EventMessage;
import weixin.popular.bean.message.message.Message;
import weixin.popular.bean.message.message.TextMessage;
import weixin.popular.support.ExpireKey;
import weixin.popular.support.expirekey.DefaultExpireKey;
import weixin.popular.util.SignatureUtil;
import weixin.popular.util.StreamUtils;
import weixin.popular.util.XMLConverUtil;

import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by booyool on 2016/11/15 0015.
 * 公众号第三方平台ComponentAccessToken及AuthorizerAccessToken管理示例代码
 */
public class AccessManageExample {
    private static String appId = "";			//component_appid 通过微信后台获取
    private static String appSecret = "";       //component_appSecret通过微信后台获取
    private static String token = "";			//component_token 通过微信后台获取
    private static String encodingToken = "";		//Token(令牌)   通过微信后台获取  qy_token
    private static String encodingAesKey = "";		//EncodingAESKey(消息加解密密钥) 通过微信后台获取

    private static String componentVerifyTicket="";  //库中不保存
    private static final int INTERVAL_TIME = 5400000;//90 min 间隔时间
    private static final String ComponentLoginPageUrl="http://.../act/showSet";//返回地址

    private static Long c_time;//保存ComponentAccessToken更新时间
    private static ComponentAccessToken c_token;//保存ComponentAccessToken

    private static Map<String,Long> a_time_map = new HashMap<String,Long>();//保存AuthorizerAccessToken更新时间
    private static Map<String,AuthorizerAccessToken> a_token_map = new HashMap<String, AuthorizerAccessToken>();//保存AuthorizerAccessToken


    private void initialize(){
        /* 从数据库获取保存的信息项。
        this.appId = ... ;
        this.appSecret = ... ;
        this.token = ... ;
        this.encodingToken = ... ;
        this.encodingAesKey = ... ;
        this.c_time = ... ;
        this.c_token = new ComponentAccessToken();
        this.c_token.setComponent_access_token( ... );//qy_secret_key
        */
    }

    public ComponentAccessToken getComponentAccessToken() {
        if(c_time==null||c_token==null||c_token.getComponent_access_token()==null){
            this.c_token = new ComponentAccessToken();
            /* 从数据库获取保存的信息项。
            this.appId = ... ;
            this.appSecret = ... ;
            this.token = ... ;
            this.encodingToken = ... ;
            this.encodingAesKey = ... ;
            this.c_time = ... ;
            this.c_token.setComponent_access_token( ... );
            */
        }
        if(c_time+INTERVAL_TIME<System.currentTimeMillis()||c_token.getComponent_access_token()==null){
            //请求新 ComponentAccessToken
            c_token = ComponentAPI.api_component_token(appId, appSecret, componentVerifyTicket);
            c_time = System.currentTimeMillis();
            if(c_token.getComponent_access_token()!=null){
                /* 更新生成的component_access_token 和 对应生成时间到数据库*/
            }
        }
        return c_token;
    }


    public AuthorizerAccessToken getAuthorizerAccessToken(String authorizerAppid) {
        AuthorizerAccessToken a_token = a_token_map.get(authorizerAppid);
        Long a_time = a_time_map.get(authorizerAppid);
        if(a_token==null||a_time==null||a_token.getAuthorizer_refresh_token()==null){
            /* 数据库获取a_token和时间信息
            a_token = new AuthorizerAccessToken();
            a_token.setAuthorizer_access_token( ... );
            a_token.setAuthorizer_refresh_token( ... );
            a_token.setExpires_in( ... );
            a_time =  ... ;
            a_token_map.put(authorizerAppid,a_token);
            a_time_map.put(authorizerAppid,a_time);
            */
        }
        if(a_time+INTERVAL_TIME<System.currentTimeMillis()||a_token.getAuthorizer_access_token()==null){
            //请求新 AuthorizerAccessToken
            ComponentAccessToken componentAccessToken = getComponentAccessToken();
            a_token = ComponentAPI.api_authorizer_token(componentAccessToken.getComponent_access_token(),
                    appId, authorizerAppid, a_token.getAuthorizer_refresh_token());
            a_time = System.currentTimeMillis();
            a_token_map.remove(authorizerAppid);
            a_token_map.put(authorizerAppid,a_token);
            a_time_map.remove(authorizerAppid);
            a_time_map.put(authorizerAppid,a_time);
            if(a_token.getAuthorizer_access_token()!=null){
                /* 更新生成的Authorizer_access_token 和 对应生成时间到数据库*/
            }
        }
        return a_token_map.get(authorizerAppid);
    }


    //重复通知过滤
    private static ExpireKey expireKey = new DefaultExpireKey();
    public void intercept(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if("".equals(appId)){initialize();}//初始化数据
        ServletInputStream inputStream = request.getInputStream();
        ServletOutputStream outputStream = response.getOutputStream();
        String signature = request.getParameter("signature");
        String timestamp = request.getParameter("timestamp");
        String nonce = request.getParameter("nonce");
        String echostr = request.getParameter("echostr");

        //加密模式
        String encrypt_type = request.getParameter("encrypt_type");
        String msg_signature = request.getParameter("msg_signature");

        WXBizMsgCrypt wxBizMsgCrypt = null;
        //加密方式
        boolean isAes = "aes".equals(encrypt_type);
        if(isAes){
            try {
                wxBizMsgCrypt = new WXBizMsgCrypt(encodingToken, encodingAesKey, appId);
            } catch (AesException e) {
                e.printStackTrace();
            }
        }

        //首次请求申请验证,返回echostr
        if(isAes&&echostr!=null){
            try {
                echostr = URLDecoder.decode(echostr, "utf-8");
                String echostr_decrypt = wxBizMsgCrypt.verifyUrl(msg_signature, timestamp, nonce, echostr);
                outputStreamWrite(outputStream,echostr_decrypt);
                return;
            } catch (AesException e) {
                e.printStackTrace();
            }
        }else if(echostr!=null){
            outputStreamWrite(outputStream,echostr);
            return;
        }

        EventMessage eventMessage = null;
        if(isAes){
            try {
                //获取XML数据（含加密参数）
                String postData = StreamUtils.copyToString(inputStream, Charset.forName("utf-8"));
                //解密XML 数据
                String xmlData = wxBizMsgCrypt.decryptMsg(msg_signature, timestamp, nonce, postData);
                System.out.println(xmlData);
                //XML 转换为bean 对象
                ComponentReceiveXML componentReceiveXML= XMLConverUtil.convertToObject(ComponentReceiveXML.class, xmlData);
                componentVerifyTicket = componentReceiveXML.getComponentVerifyTicket();
                eventMessage = XMLConverUtil.convertToObject(EventMessage.class, xmlData);
                getComponentAccessToken();//每次推送检查一下ComponentAccessToken是否需要刷新。
            } catch (AesException e) {
                e.printStackTrace();
            }
        }else{
            //验证请求签名
            if(!signature.equals(SignatureUtil.generateEventMessageSignature(token, timestamp, nonce))){
                System.out.println("The request signature is invalid");
                return;
            }

            if(inputStream!=null){
                //XML 转换为bean 对象
                eventMessage = XMLConverUtil.convertToObject(EventMessage.class, inputStream);
            }
        }

        String key = eventMessage.getFromUserName() + "__"
                + eventMessage.getToUserName() + "__"
                + eventMessage.getMsgId() + "__"
                + eventMessage.getCreateTime();
        if(expireKey.exists(key)){
            //重复通知不作处理
            return;
        }else{
            expireKey.add(key);
        }

//        //创建回复
//        XMLMessage xmlTextMessage = new XMLTextMessage(
//                eventMessage.getFromUserName(),
//                eventMessage.getToUserName(),
//                "你好");
//        //回复
//        xmlTextMessage.outputStreamWrite(outputStream,wxBizMsgCrypt);

    }

    /**
     * 数据流输出
     * @param outputStream
     * @param text
     * @return
     */
    private boolean outputStreamWrite(OutputStream outputStream,String text){
        try {
            outputStream.write(text.getBytes("utf-8"));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * 示例 -- 获取预授权码
     * @return
     */
    public PreAuthCode getCreatePreauthcode(){
        ComponentAccessToken componentAccessToken = getComponentAccessToken();
        return ComponentAPI.api_create_preauthcode(componentAccessToken.getComponent_access_token(), appId);
    }

    /**
     * 示例 -- 生成授权页 URL
     * @return
     */
    public String componentloginpage(){
        PreAuthCode preAuthCode = getCreatePreauthcode();
        return ComponentAPI.componentloginpage(appId, preAuthCode.getPre_auth_code(), ComponentLoginPageUrl);

    }

    /**
     * 示例 -- 发送会话消息
     * @param authorizerAppid
     * @param toUser
     */
    public void testSayTo(String authorizerAppid, String toUser) {
        Message m = new TextMessage(toUser,"测试发送消息");
        AuthorizerAccessToken a = getAuthorizerAccessToken(authorizerAppid);
        MessageAPI.messageCustomSend(a.getAuthorizer_access_token(), m);
    }

}
