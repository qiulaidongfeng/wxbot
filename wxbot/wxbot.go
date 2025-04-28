package wxbot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"unsafe"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/argon2"
)

var Log *slog.Logger

func SetLog(w io.Writer) {
	Log = slog.New(slog.NewTextHandler(w, nil))
}

func init() {
	SetLog(os.Stdout)
}

// 定义接收微信消息的结构体
type WeChatMessage struct {
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
	MsgId        int64  `xml:"MsgId"`
}

// 定义返回给微信服务器的消息结构体
type WeChatResponse struct {
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
}

func Handle(s *gin.Engine) {
	/*
		<xml>
		  <ToUserName><![CDATA[toUser]]></ToUserName>
		  <FromUserName><![CDATA[fromUser]]></FromUserName>
		  <CreateTime>1348831860</CreateTime>
		  <MsgType><![CDATA[text]]></MsgType>
		  <Content><![CDATA[this is a test]]></Content>
		  <MsgId>1234567890123456</MsgId>
		  <MsgDataId>xxxx</MsgDataId>
		  <Idx>xxxx</Idx>
		</xml>
	*/
	s.POST("/", func(ctx *gin.Context) {
		// 解析收到的消息
		b, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			panic(err)
		}
		if len(b) > 32*1024 { //大于32kb的消息(约1万多汉字 utf-8编码)判定为恶意攻击
			// TODO:发送者拉入黑名单
			// TODO:更灵敏的判断规则，比如发送次数异常的多（例如1秒1条）
			return
		}
		var msg WeChatMessage
		err = xml.Unmarshal(b, &msg)
		if err != nil {
			panic(err)
		}

		// 处理收到的消息
		var result string
		if strings.HasPrefix(msg.Content, "加密密码") {
			result, err = encrypt(msg.Content)
			if err != nil {
				result = err.Error()
			}
		} else if strings.HasPrefix(msg.Content, "解密密码") {
			result, err = decrypt(msg.Content)
			if err != nil {
				result = err.Error()
			}
		} else if strings.Contains(msg.Content, "帮助") {
			// 使用strings.Contains确保在指令前后意外输入空格时仍然能返回帮助。
			// Note: 这里可以安全的使用关键词匹配，而不用担心错误匹配到要加密的内容等非指令。
			result = `此机器人目前支持以下功能：
加解密 消息格式应该类似
加密密码123456
内容abcd

更多功能，敬请期待。
`
		} else {
			result = "未知的操作"
		}

		// 构造响应消息
		response := WeChatResponse{
			ToUserName:   msg.FromUserName,
			FromUserName: msg.ToUserName,
			CreateTime:   msg.CreateTime,
			MsgType:      msg.MsgType,
			Content:      result,
		}

		// 将响应消息转为 XML 格式
		xmlResponse, err := xml.MarshalIndent(response, "", "  ")
		if err != nil {
			panic(err)
		}

		// 返回响应
		ctx.Header("Content-Type", "application/xml")
		ctx.String(http.StatusOK, "此消息由机器人自动回复：\n")
		ctx.String(http.StatusOK, unsafe.String(unsafe.SliceData(xmlResponse), len(xmlResponse)))
	})
}

var grammar = errors.New(`格式错误：应该类似
加密密码123456
内容abcd
`)

func parser(msg string) ([]string, error) {
	//消息格式
	//(加|解)密密码12345678\n内容xxxx
	msg = msg[4:]
	set := strings.SplitN(msg, "\n", 1)
	if len(set) != 2 {
		return nil, grammar
	}
	if !strings.HasPrefix(set[1], "内容") {
		return nil, grammar
	}
	set[1] = set[1][2:]
	return set, nil
}

func encrypt(msg string) (string, error) {
	set, err := parser(msg)
	if err != nil {
		return "", err
	}
	return aes256_encrypt(set[0], set[1]), nil
}

func decrypt(msg string) (string, error) {
	set, err := parser(msg)
	if err != nil {
		return "", err
	}
	return aes256_decrypt(set[0], set[1]), nil
}

func genkey(password string) cipher.AEAD {
	p := unsafe.Slice(unsafe.StringData(password), len(password))
	salt := sha256.Sum256(p)
	aeskey := argon2.IDKey(p, salt[:], 1, 64*1024, 4, 32)
	c, err := aes.NewCipher(aeskey)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCMWithRandomNonce(c)
	if err != nil {
		panic(err)
	}
	return a
}

func aes256_encrypt(password string, content string) string {
	//TODO: Public this.
	a := genkey(password)
	return base64.StdEncoding.EncodeToString((a.Seal(nil, nil, unsafe.Slice(unsafe.StringData(content), len(content)), nil)))
}

func aes256_decrypt(password string, content string) string {
	//TODO: Public this.
	a := genkey(password)

	msg, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "解密失败：可能是密文不完整或密码错误"
	}
	b, err := a.Open(nil, nil, msg, nil)
	if err != nil {
		return "解密失败：可能是密文不完整或密码错误"
	}

	return base64.StdEncoding.EncodeToString((a.Seal(nil, nil, b, nil)))
}

//TODO: add test.
