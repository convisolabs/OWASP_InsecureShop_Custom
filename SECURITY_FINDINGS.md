### InsecureShop - Relatório de Vulnerabilidades (AppSec)

#### Escopo
- Revisão estática do código-fonte e manifesto do app Android (Kotlin) nesta base.
- Versões alvo: compileSdk 29, targetSdk 29, minSdk 16.

#### Sumário Executivo
- Achados críticos: carregamento de código de terceiros com `CONTEXT_INCLUDE_CODE`, WebViews carregando URLs arbitrárias e ignorando erros de SSL, vazamento e armazenamento inseguro de credenciais, ContentProvider exportado expondo credenciais, FileProvider com compartilhamento amplo (root), uso de intents implícitas/broadcasts sem restrição.
- Risco elevado de: execução arbitrária, phishing, MITM, exfiltração de arquivos/dados, interceptação/abuso de intents, acesso indevido a credenciais.

---

### Achados Detalhados

#### 1) Credenciais hardcoded (Hardcoded Credentials)
- Descrição: Credenciais embutidas no código-fonte (usuário/senha fixos).
- Evidência:
```12:16:app/src/main/java/com/insecureshop/util/Util.kt
private fun getUserCreds(): HashMap<String,String> {
    val userCreds = HashMap<String, String>()
    userCreds["shopuser"] = "!ns3csh0p"
    return userCreds
}
```
- Impacto: Facilita autenticação indevida por qualquer ator que leia o APK/código.
- Recomendações: Remover credenciais hardcoded; usar backend/IdP seguro; segredos em backend/keystore; MFA.

#### 2) Armazenamento inseguro de credenciais (Insecure Data Storage)
- Descrição: `SharedPreferences` sem criptografia para usuário e senha.
- Evidência:
```26:36:app/src/main/java/com/insecureshop/util/Prefs.kt
var username: String?
    get() = sharedpreferences.getString("username","")
    set(value) {
        sharedpreferences.edit().putString("username", value).apply()
    }

var password: String?
    get() = sharedpreferences.getString("password","")
    set(value) {
        sharedpreferences.edit().putString("password", value).apply()
    }
```
- Impacto: Exposição de credenciais por backup/ADB/root/malware.
- Recomendações: Criptografar (Jetpack Security Crypto); usar armazenamento de credenciais do Android (AccountManager/Keystore); evitar guardar senhas.

#### 3) Vazamento de credenciais em logs (Insecure Logging)
- Descrição: Usuário e senha enviados para Logcat.
- Evidência:
```39:41:app/src/main/java/com/insecureshop/LoginActivity.kt
Log.d("userName", username)
Log.d("password", password)
```
- Impacto: Qualquer app com READ_LOGS (ou depuração local) pode capturar credenciais.
- Recomendações: Remover logs sensíveis; usar mascaramento e níveis de log adequados; desabilitar logs em release.

#### 4) Execução de código de terceiros (Arbitrary Code Execution)
- Descrição: Carrega contexto de pacotes externos com `CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY` e reflete classe arbitrária.
- Evidência:
```51:63:app/src/main/java/com/insecureshop/LoginActivity.kt
val packageContext = createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY)
val value: Any = packageContext.classLoader
    .loadClass("com.insecureshopapp.MainInterface")
    .getMethod("getInstance", Context::class.java)
    .invoke(null, this)
```
- Impacto: Execução de código arbitrário, escalonando para RCE/comprometimento total.
- Recomendações: Remover esta lógica; se necessário, usar IPC controlado (Binder), assinatura verificada, verificação de integridade e assinatura do pacote alvo.

#### 5) Validação fraca de URLs e carregamento arbitrário em WebView
- Descrição: WebViews carregam URLs de dados externos (deeplink/extras) sem validação robusta; verificação por `endsWith` é insuficiente.
- Evidência:
```31:39:app/src/main/java/com/insecureshop/WebViewActivity.kt
if (uri.path.equals("/web")) {
    data = intent.data?.getQueryParameter("url")
} else if (uri.path.equals("/webview")) {
    if (intent.data!!.getQueryParameter("url")!!.endsWith("insecureshopapp.com")) {
        data = intent.data?.getQueryParameter("url")
    }
}
```
```35:41:app/src/main/java/com/insecureshop/WebView2Activity.kt
if (!intent.dataString.isNullOrBlank()) {
    webview.loadUrl(intent.dataString)
} else if (!intent.data?.getQueryParameter("url").isNullOrBlank()) {
    webview.loadUrl(intent.data?.getQueryParameter("url"))
} else if(!intent.extras?.getString("url").isNullOrEmpty()){
    webview.loadUrl(intent.extras?.getString("url"))
}
```
- Impacto: Phishing, XSS (com JS ativo), exfiltração de dados.
- Recomendações: Validar esquema/host/porta via lista de permissão estrita (URL parser, comparação de host exata); rejeitar `file://`, `javascript:`, `intent:`, etc.; usar WebViewClient que bloqueie navegação não confiável.

#### 6) Ignora erros de SSL (Lack of SSL Validation)
- Descrição: `onReceivedSslError` chama `proceed()` sempre.
- Evidência:
```10:12:app/src/main/java/com/insecureshop/util/CustomWebViewClient.kt
override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
    handler?.proceed()
}
```
- Impacto: MITM transparente; tráfego sensível exposto.
- Recomendações: Remover override inseguro; aplicar validação padrão; considerar certificate pinning via Network Security Config.

#### 7) Configuração insegura de WebView (JS + File URL Access)
- Descrição: `javaScriptEnabled = true` e `allowUniversalAccessFromFileURLs = true` em `WebViewActivity`, `WebView2Activity`, `PrivateActivity`.
- Impacto: XSS, leitura de arquivos locais e exfiltração via file:// -> http(s).
- Recomendações: Desabilitar `allowUniversalAccessFromFileURLs`; habilitar JS apenas quando estritamente necessário; isolar conteúdo não confiável.

#### 8) Intent injection via `extra_intent`
- Descrição: Activity inicia `Intent` fornecido por terceiros sem validação.
- Evidência:
```21:26:app/src/main/java/com/insecureshop/WebView2Activity.kt
val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
if (extraIntent != null) {
    startActivity(extraIntent)
    finish()
    return
}
```
- Impacto: Lançamento de componentes protegidos/privados, escalada de privilégios.
- Recomendações: Não aceitar intents aninhados; se inevitável, validar componente/ação/pacote alvo explicitamente.

#### 9) Exposição de credenciais via Broadcast implícito
- Descrição: Envia username/senha por broadcast sem delimitar destinatário.
- Evidência:
```28:36:app/src/main/java/com/insecureshop/AboutUsActivity.kt
val intent = Intent("com.insecureshop.action.BROADCAST")
intent.putExtra("username", userName)
intent.putExtra("password", password)
sendBroadcast(intent)
```
- Impacto: Qualquer app pode interceptar; vazamento de credenciais.
- Recomendações: Usar broadcast explícito (component/pacote), permissões de broadcast, ou IPC seguro.

#### 10) Componentes expostos e intent-filters permissivos
- Descrição: Activities com `BROWSABLE` e sem restrições adequadas; `AboutUsActivity` e `ResultActivity` exportadas.
- Evidência (exemplos):
```57:66:app/src/main/AndroidManifest.xml
<activity android:name=".WebViewActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:host="com.insecureshop" android:scheme="insecureshop" />
    </intent-filter>
</activity>
```
```68:74:app/src/main/AndroidManifest.xml
<activity android:name=".WebView2Activity">
    <intent-filter>
        <action android:name="com.insecureshop.action.WEBVIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
    </intent-filter>
</activity>
```
```46:47:app/src/main/AndroidManifest.xml
<activity android:name=".AboutUsActivity" android:exported="true" />
```
```81:81:app/src/main/AndroidManifest.xml
<activity android:name=".ResultActivity" android:exported="true"/>
```
- Impacto: Atores externos podem acionar telas/fluxos internos.
- Recomendações: Definir `android:exported="false"` quando possível; restringir intent-filters; validação de origem.

#### 11) Implementação insegura de `setResult` em Activity exportada
- Descrição: `ResultActivity` retorna o `Intent` recebido a quem a iniciou.
- Evidência:
```9:13:app/src/main/java/com/insecureshop/ResultActivity.kt
setResult(-1, intent)
```
- Impacto: Reflection/abuso de URIs/intent extras; acesso a providers.
- Recomendações: Não refletir intents de entrada; construir respostas estáticas e validadas.

#### 12) ContentProvider exportado expondo credenciais
- Descrição: Provider exportado retorna `username`/`password`; permissão custom não define `protectionLevel` explícito.
- Evidência:
```82:86:app/src/main/AndroidManifest.xml
<provider android:name=".contentProvider.InsecureShopProvider" android:authorities="com.insecureshop.provider" android:exported="true" android:readPermission="com.insecureshop.permission.READ" />
```
```32:35:app/src/main/java/com/insecureshop/contentProvider/InsecureShopProvider.kt
val cursor = MatrixCursor(arrayOf("username", "password"))
cursor.addRow(arrayOf<String>(Prefs.username!!, Prefs.password!!))
```
```10:11:app/src/main/AndroidManifest.xml
<permission android:name="com.insecureshop.permission.READ" />
```
- Impacto: Apps de terceiros podem ler credenciais.
- Recomendações: Tornar provider não exportado; remover dados sensíveis; exigir permissões com `protectionLevel="signature"`; checar `callingUid`.

#### 13) FileProvider com compartilhamento amplo (root-path)
- Descrição: `provider_paths.xml` permite `root-path "/"`.
- Evidência:
```1:6:app/src/main/res/xml/provider_paths.xml
<paths ...>
    <root-path name="root" path="/" />
</paths>
```
- Impacto: Superfície para exfiltração de arquivos se URIs forem concedidas.
- Recomendações: Restringir a diretórios específicos (`files-path`, `cache-path`, etc.).

#### 14) Cleartext traffic habilitado
- Descrição: `android:usesCleartextTraffic="true"` no `Application`.
- Evidência:
```20:20:app/src/main/AndroidManifest.xml
android:usesCleartextTraffic="true"
```
- Impacto: Tráfego HTTP sem criptografia sujeito a MITM.
- Recomendações: Desabilitar cleartext; usar HTTPS; configurar Network Security Config.

#### 15) Receiver dinâmico para abrir URL sem validação
- Descrição: Receiver consome `web_url` e inicia `WebView2Activity` sem validação.
- Evidência:
```10:15:app/src/main/java/com/insecureshop/CustomReceiver.kt
val stringExtra = intent?.extras?.getString("web_url")
if (!stringExtra.isNullOrBlank()) {
    val intent = Intent(context, WebView2Activity::class.java)
    intent.putExtra("url",stringExtra)
    context?.startActivity(intent)
}
```
- Impacto: Navegação forçada para URLs maliciosas.
- Recomendações: Validar URL; exigir permissão no broadcast; usar componente explícito.

#### 16) Implicit intents suscetíveis a interceptação/abuso
- Descrição: Uso extensivo de `Intent` implícitos e broadcasts sem restrições.
- Evidência (exemplos):
```52:55:app/src/main/java/com/insecureshop/ProductAdapter.kt
val intent = Intent("com.insecureshop.action.PRODUCT_DETAIL")
intent.putExtra("url", prodDetail.url)
context.sendBroadcast(intent)
```
```9:13:app/src/main/java/com/insecureshop/broadcast/ProductDetailBroadCast.kt
val webViewIntent = Intent("com.insecureshop.action.WEBVIEW")
webViewIntent.putExtra("url","https://www.insecureshopapp.com/")
context?.startActivity(webViewIntent)
```
```23:31:app/src/main/java/com/insecureshop/SendingDataViaActionActivity.kt
val intent = Intent("com.insecureshop.action.WEBVIEW")
intent.putExtra("url", "https://www.insecureshop.com/")
startActivity(intent)
```
- Impacto: Hijacking de intents, navegação indesejada, escalada de privilégios.
- Recomendações: Preferir intents explícitos; restringir receivers com permissões; validar origem.

#### 17) Exfiltração de arquivos via `ChooserActivity`
- Descrição: Converte URI em `file://` e copia para armazenamento externo; manuseio de URIs perigoso.
- Evidência:
```23:26:app/src/main/java/com/insecureshop/ChooserActivity.kt
var uri = intent.getParcelableExtra<Parcelable>("android.intent.extra.STREAM") as Uri
uri = Uri.fromFile(File(uri.toString()))
makeTempCopy(uri, getFilename(uri))
```
```31:43:app/src/main/java/com/insecureshop/ChooserActivity.kt
val path : String = Environment.getExternalStorageDirectory().absolutePath + File.separator + "insecureshop";
...
val inputStream: InputStream? = contentResolver.openInputStream(fileUri)
val outputStream: OutputStream? = contentResolver.openOutputStream(out)
```
- Impacto: Vazamento/armazenamento inseguro de arquivos em external storage.
- Recomendações: Usar `ContentResolver` com URIs de origem; evitar conversão para `file://`; utilizar `getExternalFilesDir`/`cache` e `FLAG_GRANT_*` com escopo mínimo.

#### 18) Permissões e configurações com risco de privacidade
- Descrição: `READ_CONTACTS` solicitado sem uso aparente; `allowBackup="true"` habilitado.
- Evidência:
```5:19:app/src/main/AndroidManifest.xml
<uses-permission android:name="android.permission.READ_CONTACTS" />
...
android:allowBackup="true"
```
- Impacto: Superfície de ataque e vazamento por backup.
- Recomendações: Remover permissões não usadas; desabilitar backup ou usar `fullBackupContent` com exclusões.

#### 19) Dependências desatualizadas (potenciais CVEs)
- Descrição: Bibliotecas antigas podem conter vulnerabilidades conhecidas.
- Evidência (exemplos):
```32:48:app/build.gradle
appcompat:1.1.0, core-ktx:1.3.0, constraintlayout:1.1.3,
junit:4.12, glide:4.11.0, gson:2.8.6, uploadservice:3.2.3
```
- Impacto: Exploração de falhas conhecidas em libs.
- Recomendações: Atualizar para versões suportadas; executar SCA (OWASP Dependency-Check/Gradle Versions Plugin).

---

### Itens de Configuração de Rede
- `usesCleartextTraffic = true` habilita HTTP; considerar Network Security Config e pinagem de certificado.

### Observações Gerais
- Preferir intents explícitos e validações estritas.
- Evitar expor dados/funcionalidades via componentes exportados sem necessidade.
- Implementar defesa em profundidade: validação de entrada, princípio do menor privilégio, redução de superfície.

### Referências
- OWASP MASVS/MSTG
- OWASP Mobile Top 10
- Android Security Best Practices (WebView, Intents, ContentProvider, FileProvider) 