import os
import streamlit as st
import sqlalchemy
import pandas as pd
import ipaddress
import random
import string
from google.cloud.sql.connector import Connector, IPTypes
from passlib.hash import des_crypt
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime, timedelta


# 1. ページ設定（ついでにタイトルなども設定）
st.set_page_config(page_title="DDST Portal", layout="wide")

# 2. CSSを注入してメニューとフッターを非表示にする
hide_style = """
    <style>
    #MainMenu {visibility: hidden;}          /* 右上のメニューボタン */
    footer {visibility: hidden;}            /* 下部のMade with Streamlit */
    header {visibility: hidden;}            /* 上部のヘッダーバー全体 */
    #stDecoration {display:none;}           /* 上部のカラフルなライン */
    </style>
"""
st.markdown(hide_style, unsafe_allow_html=True)

# --- タイムアウト設定 ---
TIMEOUT_HOURS = 2

def check_timeout():
    """現在の時刻と最終認証時刻を比較して、2時間を超えていたらセッションを切る"""
    
    # すでに認証済みのユーザーに対してのみチェック
    if "authenticated_at" in st.session_state:
        elapsed_time = datetime.now() - st.session_state.authenticated_at
        
        # 2時間を超えていた場合
        if elapsed_time > timedelta(hours=TIMEOUT_HOURS):
            # 全セッション情報をクリア（認証フラグ、OTPフラグなど全て消える）
            st.session_state.clear()
            st.warning("⚠️ セッションの有効期限（2時間）が切れました。再度ログインしてください。")
            st.stop()  # ここで処理を中断して再認証画面へ
    
    # ログイン（OTP認証）成功時にこのフラグを立てる必要がある
    # 例: if otp_success: st.session_state.authenticated_at = datetime.now()

# アプリの冒頭で実行
check_timeout()

# ==========================================
# 1. ページ設定とIP制限
# ==========================================
st.set_page_config(
    page_title="Internal ADST Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def check_ip_restriction():
    """アクセス元IPのホワイトリストチェック"""
    ALLOWED_LIST = [
        ipaddress.ip_network("131.113.0.0/16"),
        ipaddress.ip_network("150.195.208.103/32"),
        ipaddress.ip_network("140.82.207.175/32"),
        ipaddress.ip_network("150.195.219.99/32")
    ]
    
    forwarded_ips = st.context.headers.get("X-Forwarded-For", "")
    
    # Cloud Run環境でのみIP制限を有効化（ローカル開発時はスキップ）
    if os.environ.get("K_SERVICE"):
        if not forwarded_ips:
            st.error("Access Denied: No source IP identified.")
            st.stop()
            
        client_ip_str = forwarded_ips.split(",")[0].strip()
        client_ip = ipaddress.ip_address(client_ip_str)
        if not any(client_ip in net for net in ALLOWED_LIST):
            st.error(f"Access Denied: Your IP ({client_ip_str}) is not authorized.")
            st.stop()

check_ip_restriction()

# ==========================================
# 2. データベース接続 (Cloud SQL)
# ==========================================
@st.cache_resource
def get_engine():
    connector = Connector()
    def getconn():
        conn = connector.connect(
            instance_connection_string=os.environ.get("INSTANCE_CONNECTION_NAME"),
            driver="pg8000",
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASS"),
            db=os.environ.get("DB_NAME"),
            ip_type=IPTypes.PUBLIC
        )
        # 接続ごとに日本時刻を設定
        cursor = conn.cursor()
        cursor.execute("SET TIME ZONE 'Asia/Tokyo'")
        return conn
    return sqlalchemy.create_engine("postgresql+pg8000://", creator=getconn)

engine = get_engine()

# ==========================================
# 3. 共通ユーティリティ
# ==========================================
def generate_pass():
    return ''.join(random.choices(string.ascii_letters, k=4)) + ''.join(random.choices(string.digits, k=4))

def hash_password(password):
    return des_crypt.hash(password)

# ==========================================
# 3. 認証・メール送信関数
# ==========================================

def send_otp_mail(target_email, otp_code):
    api_key = os.environ.get('SENDGRID_API_KEY')
    if not api_key:
        st.error("SENDGRID_API_KEY が設定されていません。")
        return False

    message = Mail(
        from_email='no-reply-shogai@keio.jp',
        to_emails=target_email,
        subject='【DDST Portal】二段階認証コード',
        plain_text_content=f'認証コードは {otp_code} です。'
    )
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        st.error(f"メール送信エラー: {e}")
        return False

def iap_login_screen():  
    raw_email = st.context.headers.get("X-Goog-Authenticated-User-Email")
    if not raw_email:
        if os.environ.get("K_SERVICE"):
            st.error("IAP authentication failed.")
            st.stop()
        return "local-test@keio.jp"
    return raw_email.replace("accounts.google.com:", "")

# --- 実行 ---
current_user_email = iap_login_screen()

# ==========================================
# 4. ログイン画面（二段階認証対応）
# ==========================================
def login_screen():
    if st.session_state.get("authenticated") and st.session_state.get("otp_verified"):
        return st.session_state.get("username")

    st.title("🔐 DDST Portal Login")
    st.info(f"Googleアカウント: {current_user_email}")

    # Step 1: ID/PW
    if not st.session_state.get("authenticated"):
        user_id = st.text_input("ログインID")
        password = st.text_input("パスワード", type="password")

        if st.button("ログイン"):
            with engine.connect() as conn:
                sql = sqlalchemy.text("SELECT xc04applusrpwd, xc04applctrlif2 FROM x.xc04 WHERE xc04applusrid = :id")
                res = conn.execute(sql, {"id": user_id}).fetchone()
                
                if res and des_crypt.verify(password, res[0].strip()):
                    otp = str(random.randint(1000, 9999))
                    if send_otp_mail(current_user_email, otp):
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = user_id
                        st.session_state["permissions"] = res[1] or "0"*10
                        st.session_state["otp_code"] = otp
                        st.success("認証コードを送信しました。")
                        st.rerun()
                    else:
                        st.error("メール送信に失敗しました。")
                else:
                    st.error("IDまたはパスワードが正しくありません")
    
    # Step 2: OTP
    else:
        otp_input = st.text_input("上記のE-Mailアドレスに送信した認証コード(4桁)", max_chars=4)
        if st.button("認証実行"):
            if otp_input == st.session_state.get("otp_code"):
                st.session_state["otp_verified"] = True
                st.rerun()
            else:
                st.error("コードが一致しません")
        if st.button("キャンセル"):
            st.session_state.clear()
            st.rerun()
    st.stop()

# ログインチェック
current_user = login_screen()

# --- ログインチェック部分のイメージ ---
# パスワード照合成功後
try:
        with engine.connect() as conn:
            # 権限フラグを取得
            perm_sql = sqlalchemy.text("SELECT xc04applctrlif2 FROM x.xc04 WHERE xc04applusrid = :id")
            perm_result = conn.execute(perm_sql, {"id": current_user}).fetchone()
            
            if perm_result:
                # 10文字の文字列を取得（例: "1100000000"）
                permissions = perm_result[0] 
                st.session_state.permissions = permissions
            else:
                # 権限設定がない場合のデフォルト
                st.session_state.permissions = "0" * 10
                
except Exception as e:
        st.error(f"権限情報の取得に失敗しました: {e}")
        st.session_state.permissions = "0" * 10
        
# 権限フラグを取得（未定義なら全拒否の文字列）
perms = st.session_state.get("permissions", "0" * 10)

# ==========================================
# データ取得用ユーティリティ（キャッシュ活用）
# ==========================================

@st.cache_data(ttl=3600)  # 1時間キャッシュ
def get_master_data():
    """卒業年範囲と学部リストを取得"""
    with engine.connect() as conn:
        # 1. 卒業年の最小・最大取得
        grad_sql = "SELECT MIN(EXTRACT(YEAR FROM da06gradyd)), MAX(EXTRACT(YEAR FROM da06gradyd)) FROM d.da06"
        min_y, max_y = conn.execute(sqlalchemy.text(grad_sql)).fetchone()
        
        # 2. 学部リスト取得
        dept_sql = "SELECT az19fcd, az19fskj FROM a.az19 ORDER BY az19fcd"
        depts = pd.read_sql(sqlalchemy.text(dept_sql), conn)
        
    return int(min_y or 1900), int(max_y or datetime.now().year), depts

# ==========================================
# 5. メインメニュー（サイドバー）
# ==========================================
st.sidebar.title("メニュー")
st.sidebar.info(f"User: {current_user}")
st.sidebar.info(f"keio.jp: {current_user_email}")

# メニューリストの動的生成
menu_options = []

# 例: 2文字目が '1' なら塾員検索を表示
if perms[1] == "0":
    menu_options.append("🔍 塾員検索（詳細）")
    menu_options.append("🔍 塾員検索（一般部署）")
    menu_options.append("🎓 塾員照会 (メディア用)")
    menu_options.append("📋 操作ログ閲覧")    
    # menu_options.append("🔑 パスワード変更")
    menu_options.append("📊 SFDC同期状態確認") 
    # menu_options.append("👤 新規ユーザー作成") 
    
if perms[1] == "1":
    menu_options.append("🔍 塾員検索（詳細）")
    menu_options.append("📋 操作ログ閲覧")    
    # menu_options.append("🔑 パスワード変更")

if perms[1] == "2":
    menu_options.append("🔍 塾員検索（一般部署）")
    menu_options.append("📋 操作ログ閲覧")    
    # menu_options.append("🔑 パスワード変更")

if perms[1] == "3":
    menu_options.append("🎓 塾員照会 (メディア用)")
    menu_options.append("📋 操作ログ閲覧")    

# サイドバーに反映
choice = st.sidebar.selectbox("メニュー", menu_options)

# 他のメニューも同様に条件分岐...

#choice = st.sidebar.selectbox(
#    "機能を選択してください",
#    [
#        "🔍 塾員検索", 
#        "🎓 塾員照会 (メディア用)",
#        "📋 操作ログ閲覧",
#        "📊 SFDC同期状態確認", 
#        "🔑 パスワード変更", 
#        "👤 新規ユーザー作成"
#    ],
#    index=0
#)

if st.sidebar.button("ログアウト"):
    st.session_state.clear()
    st.rerun()

# ==========================================
# 6. 各機能の表示ロジック
# ==========================================

if choice == "🔍 塾員検索（詳細）" or choice == "🔍 塾員検索（一般部署）" :
    if "sub_view" not in st.session_state:
        st.session_state.sub_view = "list"

    # --- A. リスト表示モード ---
    if st.session_state.sub_view == "list":
        st.title("🔍 塾員検索")
        
        # マスターデータの準備
        min_year, max_year, dept_df = get_master_data()
        year_options = [""] + [str(y) for y in range(max_year, min_year - 1, -1)]
        dept_options = {"": ""}
        for _, row in dept_df.iterrows():
            dept_options[row['az19fcd']] = f"{row['az19fcd']}: {row['az19fskj']}"

        # --- 検索フォーム ---
        with st.form("search_form"):
            st.markdown("### 🌐 グローバル検索")
            k1, k2, k3 = st.columns(3)
            stext1 = k1.text_input("キーワード1", placeholder="氏名、住所、勤務先など")
            stext2 = k2.text_input("キーワード2")
            stext3 = k3.text_input("キーワード3")

            st.divider()
            
            st.markdown("### 絞り込み条件")
            c1, c2, c3 = st.columns(3)
            jkinno = c1.text_input("塾員番号")
            fnm = c2.text_input("姓 (漢字/カナ)")
            lnm = c3.text_input("名 (漢字/カナ)")

            c4, c5, c6 = st.columns(3)
            birth = c4.text_input("生年月日 (YYYY-MM-DD)")
            s_grad_str = c5.selectbox("卒業年(開始)", options=year_options)
            e_grad_str = c6.selectbox("卒業年(終了)", options=year_options)

            c7, c8 = st.columns([2, 1])
            f_cd = c7.selectbox("学部", options=list(dept_options.keys()), 
                                format_func=lambda x: dept_options[x])
            bukko_flg = c8.checkbox("物故者を除外する", value=True)
            
            submit = st.form_submit_button("🔍 検索実行", type="primary", use_container_width=True)
        if submit:
            s_grad = int(s_grad_str) if s_grad_str else -1
            e_grad = int(e_grad_str) if e_grad_str else -1

            # パラメータ設定
            params = {
                "Jkinno": jkinno or "",
                "SearchText": stext1 or "",
                "SearchText2": stext2 or "",
                "SearchText3": stext3 or "",
                "FNM": fnm or "",
                "LNM": lnm or "",
                "Birth": birth or "",
                "SGrad": s_grad,
                "EGrad": e_grad,
                "Pcuser": current_user_email,
                "Appid": current_user,
                "FormId": "DW80201",
                "Pcname": "CloudRun",
                "FCd": f_cd or "",
                "Bukkoflg": bukko_flg
            }

            try:
                with engine.connect() as conn:
                    # 明示的にトランザクションを開始
                    # これによりプロシージャ内のINSERTがCOMMITされ、ログが残ります
                    with conn.begin():
                        sql = sqlalchemy.text("""
                            SELECT 
                            jkinno, nmkj, nmkn, gradyynm, keioscnm, wrknm, addr_s, birthyd
                            FROM d.da_guest_serch_web(
                                :Jkinno, :SearchText, :SearchText2, :SearchText3, 
                                :FNM, :LNM, :Birth, :SGrad, :EGrad, 
                                :Pcuser, :Appid, :FormId, :Pcname, :FCd, :Bukkoflg
                            ) ORDER BY jkinno
                        """)
                        
                        # executeで実行し、全ての結果を取得
                        result = conn.execute(sql, params)
                        rows = result.fetchall()
                        
                        # 結果をDataFrameに変換（列名を保持）
                        st.session_state.search_df = pd.DataFrame(rows, columns=result.keys())
                
                # 成功したら再描画（古い選択状態などをクリアするため）
                st.rerun()

            except Exception as e:
                st.error(f"検索処理中にエラーが発生しました: {e}")

        # --- 結果表示 ---
        if "search_df" in st.session_state:
            df = st.session_state.search_df
            
            # 0件の場合のメッセージ表示
            if df.empty:
                st.info("該当するデータが見つかりませんでした。")
            else:
                st.write(f"検索結果: {len(df)} 件 (1,000件上限)")
                
                event = st.dataframe(
                    df,
                    use_container_width=True,
                    height=600,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    column_config={
                        "jkinno": "塾員番号",
                        "nmkj": "氏名",
                        "nmkn": "カナ",
                        "gradyynm": "卒業年",
                        "keioscnm": "学部",
                        "wrknm": "勤務先",
                        "addr_s": "住所",
                        "birthyd": "生年月日"
                    }
                )

                if event.selection.rows:
                    selected_idx = event.selection.rows[0]
                    st.session_state.selected_id = df.iloc[selected_idx]["jkinno"]
                    st.session_state.sub_view = "detail"
                    st.rerun()
                    
    # --- B. 塾員詳細画面モード (if choice の内側に入れる) ---elif st.session_state.sub_view == "detail":
    elif st.session_state.sub_view == "detail":
        if st.button("⬅ 検索結果に戻る"):
            st.session_state.sub_view = "list"
            st.rerun()

        target_id = st.session_state.get("selected_id")

    # 1. データベース接続とSQL実行
        try:
            with engine.connect() as conn:
                # トランザクションを開始。これにより WHERE 句内のログ関数(d.da_detail_log)の実行が確定します。
                with conn.begin():
                    # SQL文を定義
                    detail_sql = sqlalchemy.text("""
                        SELECT
                            DA01JKINNO as 塾員番号
                            , da01stdid as 塾員学籍番号
                            , da01staffno as 塾員教職員番号
                            , da01stafffg as 塾員教職員有効フラグ
                            , (
                                (
                                    CASE 
                                        WHEN DA03FNMKJ IS NULL 
                                            THEN RTRIM(DA01FNMKJ) || '  ' || RTRIM(DA01LNMKJ) 
                                        ELSE RTRIM(DA01FNMKJ) || '  ' || RTRIM(DA01LNMKJ) 
                                    END
                                ) ::varchar || case 
                                    when rtrim(da01fnmalp) <> '' 
                                        then ' / ' || rtrim(da01fnmalp) 
                                    else '' 
                                end ::varchar || case 
                                    when rtrim(da01lnmalp) <> '' 
                                        then ' ' || rtrim(da01lnmalp) 
                                    else '' 
                                end ::varchar
                            ) ::varchar AS 氏名
                            , (
                                CASE 
                                    WHEN DA03FNMSKJ IS NULL 
                                        THEN RTRIM(DA01FNMSKJ) || '  ' || RTRIM(DA01LNMSKJ) 
                                    ELSE RTRIM(DA01FNMSKJ) || '  ' || RTRIM(DA01LNMSKJ) 
                                END
                            ) ::varchar AS 氏名（簡漢字）
                            , (RTRIM(DA01FNMKN) || '  ' || RTRIM(DA01LNMKN)) ::varchar AS 氏名（カナ）
                            , case 
                                when DA03FNMSKJ is null 
                                    then '' 
                                else (RTRIM(DA03FNMSKJ) || '  ' || RTRIM(DA03LNMSKJ)) 
                                end ::varchar AS 離籍時氏名（簡漢字）
                            , case 
                                when DA03FNMKN is null 
                                    then '' 
                                else (RTRIM(DA03FNMKN) || '  ' || RTRIM(DA03LNMKN)) 
                                end ::varchar AS 離籍時氏名（カナ）
                            , (
                                CASE 
                                    WHEN DA02FNMSKJ IS NULL 
                                        THEN '' 
                                    ELSE RTRIM(DA02FNMSKJ) || '  ' || RTRIM(DA02LNMSKJ) 
                                END
                            ) ::varchar AS 氏名補足（簡漢字）
                            , (
                                CASE 
                                    WHEN DA02FNMKN IS NULL 
                                        THEN '' 
                                    ELSE RTRIM(DA02FNMKN) || '  ' || RTRIM(DA02LNMKN) 
                                END
                            ) ::varchar AS 氏名補足（カナ）
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = da01opcd1) as 氏名公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = da01getcd1) as 氏名入手経路
                            , da06stdid as 塾員学歴学籍番号
                            , da06entryd as 入学日
                            , DA06GRADYD as 卒業日
                            , DA06GRADYYNM as 卒年（和暦）
                            , DA06BLGFCD as 学部・研究科CD
                            , RTRIM(DA06KEIOSCNM) ::varchar as 学部・研究科
                            , da06blgdepcd as 学科・専攻CD
                            , RTRIM(da06classnm) ::varchar as 学科・専攻
                            , DA01BIRTHYD AS 塾員生年月日
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = da01opcd2) as 生年月日公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = da01getcd2) as 生年月日入手経路
                            , da01zip as 郵便番号
                            , (RTRIM(XZ02PREFENM) || RTRIM(DA01ADDR2) || RTRIM(da01addr3) || RTRIM(da01addr4)) ::varchar AS 住所（国内）
                            , (RTRIM(XZ02PREFENM) || RTRIM(DA01ADDR2)) ::varchar AS 住所_省略（国内）                            
                            , (RTRIM(DA01FADDR1) || ' ' || RTRIM(DA01FADDR2) || RTRIM(DA01FADDR3)) ::varchar AS 住所（海外）
                            , (RTRIM(DA01FADDR1)) ::varchar AS 住所_省略（海外）
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD5) as 住所情報公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD5) as 住所情報入所経路
                            , DA01UPDYD5 as 住所更新年月日
                            , DA01ADDRUNIDENTFG as 住所不明フラグ
                            , DA01ADDRCONFYD as 住所情報確認年月日
                            , DA01ADDRNOTE as 住所情報備考
                            , (select dz99commonnm from d.dz99 where dz99commondv = '109' and dz99commoncd = DA01SENDCDMAIL) as 郵送物発送フラグ
                            , da01teld as 塾員電話番号（固定電話）
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD6) as 固定電話公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD6) as 固定電話入所経路
                            , da01teln as 塾員電話番号（携帯）
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD7) as 携帯電話公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD7) as 携帯電話入所経路
                            , da01fax as Fax番号
                            , da01email as EMail
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD9) as EMail公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD9) as EMail入所経路
                            , DA01DEATHFLG as 物故フラグ
                            , DA01DEATHYD as 塾員物故年月日
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD11) as 物故情報入手経路
                            , DA01UPDYD11 as 物故更新年月日
                            , CASE 
                                WHEN DA01SEXCD = '1' then '男' 
                                WHEN DA01SEXCD = '2' then '女' 
                                else '' 
                                end as 性別
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD3) as 性別公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD3) as 性別入所経路
                            , rtrim(xz01natnlkj) as 国籍
                            , (select dz99commonnm from d.dz99 where dz99commondv = '110' and dz99commoncd = DA01OPCD4) as 国籍公開
                            , (select dz99commonnm from d.dz99 where dz99commondv = '105' and dz99commoncd = DA01GETCD4) as 国籍入所経路
                            , (select dz99commonnm from d.dz99 where dz99commondv = '104' and dz99commoncd = DA01PARTYCD) as 評議員選挙
                            , DA01UPDYD12 as 更新年月日（評議員選挙）
                            , da01hyogiinsenkyohistory as 評議員選挙履歴
                            , rtrim(DA01NOTE) as 塾員情報備考
                            , da01updyd13 as 更新年月日（備考） 
                        FROM
                            D.DA01 
                            left outer join ( 
                                SELECT
                                    DA06JKINNO as DA06MINJKINNO
                                    , MIN(DA06SCCAREERNO) AS DA06MINCNT 
                                FROM D.DA06 
                                group by DA06JKINNO
                            ) AS A ON DA01JKINNO = DA06MINJKINNO 
                            left outer join D.DA06 ON DA06JKINNO = A.DA06MINJKINNO AND DA06SCCAREERNO = A.DA06MINCNT 
                            LEFT OUTER JOIN D.DA03 on DA03JKINNO = DA01JKINNO AND da03nmhisno = 1 
                            LEFT OUTER JOIN X.XZ02 ON XZ02PREFECD = DA01PREFECD 
                            LEFT OUTER JOIN ( 
                                SELECT
                                    DA02JKINNO as DA02MAXJKINNO
                                    , MAX(da02nmsubno) AS DA02MAXCNT 
                                FROM D.DA02 GROUP BY DA02JKINNO
                            ) as DA02MAX ON DA02MAXJKINNO = DA01JKINNO 
                            LEFT OUTER JOIN D.DA02 on DA02JKINNO = DA02MAXJKINNO AND da02nmsubno = DA02MAXCNT 
                            LEFT OUTER JOIN X.XZ01 on da01countrycd = xz01natnlcd 
                            LEFT OUTER JOIN D.DA01EX on DA01JKINNO=DA01EXJKINNO 
                        WHERE
                            DA01JKINNO = :jkinno
                            and d.da_detail_log(
                                        :jkinno ,
                                        :Pcuser ,
                                        :Appid ,
                                        :FormId ,
                                        :Pcname 
                                    )
                    """)
                    # パラメータ設定
                    params = {
                        "jkinno": target_id or "",
                        "Pcuser": current_user_email,
                        "Appid": current_user,
                        "FormId": "DW80202",
                        "Pcname": "CloudRun"
                    }
            # executeを実行し、結果をDataFrameに変換
                    result = conn.execute(detail_sql, params)
                    df_detail = pd.DataFrame(result.fetchall(), columns=result.keys())

            # 取得したデータをセッション等に格納する処理（必要に応じて）
            # st.session_state.detail_df = df_detail

        except Exception as e:
            st.error(f"詳細データの取得中にエラーが発生しました: {e}")
        
        if not df_detail.empty:
            r = df_detail.iloc[0]

            # --- A. 【最上段】サマリーエリア（GroupBox1） ---
            with st.container(border=True):
                s_col = st.columns([1.2, 1.2, 1, 1, 1, 1.2, 1.2])
                s_col[0].text_input("塾員番号", r['塾員番号'], disabled=True)
                s_col[1].text_input("塾員学歴学籍番号", r['塾員学籍番号'], disabled=True)
                s_col[2].text_input("入学日", r['入学日'], disabled=True)
                s_col[3].text_input("卒年(和暦)", r['卒年（和暦）'], disabled=True)
                s_col[4].text_input("卒業日", r['卒業日'], disabled=True)
                s_col[5].text_input("学部・研究科", r['学部・研究科'], disabled=True)
                s_col[6].text_input("学科・専攻", r['学科・専攻'], disabled=True)

            # --- B. メインレイアウト分割 ---
            col_left, col_right = st.columns([4.5, 5.5])

            # --- C. 【左側】プロフィール詳細パネル ---
            with col_left:
                # 1. 氏名グループ
                with st.container(border=True):
                    c1, c2, c3 = st.columns([3, 1.5, 1.5])
                    c2.caption("氏名公開")
                    # keyを追加して重複を回避
                    c2.text_input("公開", r['氏名公開'], label_visibility="collapsed", disabled=True, key="key_name_op")
                    c3.caption("氏名入手経路")
                    c3.text_input("経路", r['氏名入手経路'], label_visibility="collapsed", disabled=True, key="key_name_get")
                    
                    st.text_input("氏名", r['氏名'], disabled=True)
                    st.text_input("氏名（簡漢字）", r['氏名（簡漢字）'], disabled=True)
                    st.text_input("氏名（カナ）", r['氏名（カナ）'], disabled=True)
                    st.text_input("離籍時氏名（簡漢字）", r['離籍時氏名（簡漢字）'], disabled=True)
                    st.text_input("氏名補足（簡漢字）", r['氏名補足（簡漢字）'], disabled=True)
                    st.text_input("氏名補足（カナ）", r['氏名補足（カナ）'], disabled=True)

                # 2. 生年月日・属性グループ
                with st.container(border=True):
                    b1, b2, b3 = st.columns([2, 2, 2])
                    b1.text_input("塾員生年月日", r['塾員生年月日'], disabled=True)
                    b2.text_input("生年月日公開", r['生年月日公開'], disabled=True, key="key_birth_op")
                    b3.text_input("入手経路", r['生年月日入手経路'], disabled=True, key="key_birth_get")
                    
                    n1, n2, n3 = st.columns([2, 2, 2])
                    n1.text_input("国籍", r['国籍'], disabled=True)
                    n2.text_input("国籍公開", r['国籍公開'], disabled=True, key="key_natl_op")
                    # ここでエラーが出ていた箇所
                    n3.text_input("入手経路", r['国籍入所経路'], disabled=True, key="key_natl_get")
                    
                    g1, g2, g3 = st.columns([2, 2, 2])
                    g1.text_input("性別", r['性別'], disabled=True)
                    g2.text_input("性別公開", r['性別公開'], disabled=True, key="key_sex_op")
                    g3.text_input("入手経路", r['性別入所経路'], disabled=True, key="key_sex_get")
                
                # 3. 教職員グループ (リクエストのチェックボックス)
                with st.container(border=True):
                    st1, st2 = st.columns(2)
                    st1.text_input("塾員教職員番号", r['塾員教職員番号'], disabled=True)
                    st2.write("") # 間隔調整
                    is_staff = (r['塾員教職員有効フラグ'] == '1')
                    st2.checkbox("塾員教職員有効フラグ", value=is_staff, disabled=True)

                # 4. 住所グループ
                with st.container(border=True):
                    ad1, ad2, ad3 = st.columns([2, 2, 2])
                    ad1.text_input("郵便番号", r['郵便番号'], disabled=True)
                    is_addr_lost = (r['住所不明フラグ'] == '1')
                    ad2.text_input("住所不明確認年月日", r['住所情報確認年月日'], disabled=True)
                    #ad2.checkbox("住所不明フラグ", value=is_addr_lost, disabled=True)
                    # 住所不明判定
                    if r['住所不明フラグ'] == '1':
                        ad3.error("住所不明")
                    else:
                        ad3.success("住所有効")

                    if choice == "🔍 塾員検索（詳細）":
                        st.text_input("住所（国内）", r['住所（国内）'], disabled=True)
                        st.text_input("住所（海外）", r['住所（海外）'], disabled=True)
                        st.text_input("住所情報備考", r['住所情報備考'], disabled=True)
                    else:
                        st.text_input("住所_省略（国内）", r['住所_省略（国内）'], disabled=True)
                        st.text_input("住所_省略（海外）", r['住所_省略（海外）'], disabled=True)
                    
                    ad4, ad5, ad6 = st.columns([2, 2, 2])
                    ad4.text_input("住所情報入手経路", r['住所情報入所経路'], disabled=True)
                    ad5.text_input("住所情報公開", r['住所情報公開'], disabled=True)
                    
                    ad7, ad8 = st.columns(2)
                    ad7.text_input("郵送物発送フラグ", r['郵送物発送フラグ'], disabled=True)
                    ad8.text_input("住所更新年月日", r['住所更新年月日'], disabled=True)

                # 5. 電話・連絡先グループ
                if choice == "🔍 塾員検索（詳細）":
                    with st.container(border=True):
                        p1, p2, p3 = st.columns([2, 2, 2])
                        p1.text_input("塾員電話番号（固定電話）", r['塾員電話番号（固定電話）'], disabled=True)
                        p2.text_input("固定電話公開", r['固定電話公開'], disabled=True, key="key_tel_op")
                        p3.text_input("入手経路", r['固定電話入所経路'], disabled=True, key="key_tel_get")
                        
                        m1, m2, m3 = st.columns([2, 2, 2])
                        m1.text_input("塾員電話番号（携帯）", r['塾員電話番号（携帯）'], disabled=True)
                        m2.text_input("携帯電話公開", r['携帯電話公開'], disabled=True, key="key_mobile_op")
                        m3.text_input("入手経路", r['携帯電話入所経路'], disabled=True, key="key_mobile_get")

            # --- D. 【右側】履歴エリア（前回までの内容を集約） ---
            #with col_right:
                # 画面幅を有効活用するため、履歴はここに配置
                # ... (前回作成した 学歴履歴、住所履歴、勤務先履歴、氏名履歴 のコードをここに配置) ...
    
            with col_right:
                # 物故グループ
                with st.container(border=True):
                    d1, d2 = st.columns(2)
                    is_dead = (r['物故フラグ'] == '1')
                    #d1.checkbox("物故フラグ", value=is_dead, disabled=True)
                    d1.text_input("塾員物故年月日", r['塾員物故年月日'], disabled=True)
                    # 物故判定
                    if r['物故フラグ'] == '1':
                        d2.error("物故")
                    else:
                        d2.success("有効")
                        
                # 評議員選挙と全体備考
                if choice == "🔍 塾員検索（詳細）":
                    with st.container(border=True):
                        e1, e2 = st.columns(2)
                        e1.text_input("評議員選挙", r['評議員選挙'], disabled=True)
                        e2.text_input("更新年月日（評議員選挙）", r['更新年月日（評議員選挙）'], disabled=True)
                        st.text_area("評議員選挙履歴", r['評議員選挙履歴'], height=100, disabled=True)
                        st.text_area("塾員情報備考", r['塾員情報備考'], height=100, disabled=True)
                        st.caption(f"最終更新：{r['更新年月日（備考）']}")
                
                # Delphiの右側に並んでいる各ラベルとグリッドのプレースホルダ 
                st.markdown("#### 📑 関連履歴一覧")
    
                # --- 1. 学歴履歴 (DA06) の取得と表示 ---
                with st.expander("🎓 学歴履歴", expanded=True):
                    with engine.connect() as conn:
                        gakureki_sql = sqlalchemy.text("""
                            SELECT 
                                da06sccareerno as 連番,
                                da06entryd as 入学日,
                                da06gradyd as 卒業日,
                                da06gradyynm as 卒年,
                                da06keioscnm as "学校・学部",
                                da06classnm as "学科・専攻",
                                da06stdid as 学籍番号,
                                da06keiosctpcd,
                                da06prgcd,
                                da06blgfcd,
                                da06blgdepcd,
                                da06cls
                            FROM d.da06
                            WHERE da06jkinno = :jkinno
                            ORDER BY da06sccareerno
                        """)
                        df_gakureki = pd.read_sql(gakureki_sql, conn, params={"jkinno": target_id})
    
                    if not df_gakureki.empty:
                        st.dataframe(
                            df_gakureki,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "連番": st.column_config.NumberColumn(width="small"),
                                "入学日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                "卒業日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                "卒年": st.column_config.TextColumn(width="small"),
                                "学校・学部": st.column_config.TextColumn(width="small"),
                                "学科・専攻": st.column_config.TextColumn(width="small"),
                                "学籍番号": st.column_config.TextColumn(width="medium"),
                            }
                        )
                    else:
                        st.caption("学歴情報の登録はありません。")
    
                with st.expander("🏢 勤務先履歴", expanded=True):
                    with engine.connect() as conn:
                        kinmu_sql = sqlalchemy.text("""
                            SELECT 
                                DA07WRKNO as 履歴番号,
                                CASE WHEN DA07WRKFG = '1' THEN '現職' ELSE '旧職' END as 状態,
                                DA07WRKNM as 勤務先名,
                                DA07WRKSECT as 部署,
                                DA07WRKPOST as 役職,
                                DA07WRKNOTE as 備考,
                                DA07UPDYD1 as 更新日
                            FROM d.da07
                            WHERE da07jkinno = :jkinno
                            ORDER BY DA07WRKFG DESC, DA07WRKNO DESC
                        """)
                        df_kinmu = pd.read_sql(kinmu_sql, conn, params={"jkinno": target_id})
    
                    if not df_kinmu.empty:
                        st.dataframe(
                            df_kinmu,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "履歴番号": st.column_config.NumberColumn(width="small"),
                                "状態": st.column_config.TextColumn(width="small"),
                                "勤務先名": st.column_config.TextColumn(width="medium"),
                                "部署": st.column_config.TextColumn(width="medium"),
                                "役職": st.column_config.TextColumn(width="medium"),
                                "更新日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                            }
                        )
                    else:
                        st.caption("勤務先履歴の登録はありません。")

                with st.expander("🏠 住所履歴", expanded=True):
                    with engine.connect() as conn:
                        if choice == "🔍 塾員検索（詳細）":
                            jusho_sql = sqlalchemy.text("""
                                SELECT 
                                    DA05ADDRHISNO as 履歴番号,
                                    DA05ZIP as 郵便番号,
                                    (COALESCE(DA05ADDR2, '') || COALESCE(DA05ADDR3, '') || COALESCE(DA05ADDR4, '')) as 住所,
                                    DA05TELD as "携帯電話",
                                    DA05TELN as "固定電話",
                                    DA05EMAIL as "Eメール",
                                    DA05ADDRCONFYD as 確認日,
                                    CASE WHEN DA05ADDRUNIDENTFG = '1' THEN '不明' ELSE '有効' END as 状態,
                                    DA05ADDRHISNOTE as 備考
                                FROM d.da05
                                WHERE da05jkinno = :jkinno
                                ORDER BY DA05ADDRHISNO DESC
                            """)
                        else:
                             jusho_sql = sqlalchemy.text("""
                                SELECT 
                                    DA05ADDRHISNO as 履歴番号,
                                    DA05ZIP as 郵便番号,
                                    (COALESCE(DA05ADDR2, '')||'＊＊＊') as 住所,
                                    '＊' as "携帯電話",
                                    '＊' as "固定電話",
                                    '＊' as "Eメール",
                                    DA05ADDRCONFYD as 確認日,
                                    CASE WHEN DA05ADDRUNIDENTFG = '1' THEN '不明' ELSE '有効' END as 状態,
                                    DA05ADDRHISNOTE as 備考
                                FROM d.da05
                                WHERE da05jkinno = :jkinno
                                ORDER BY DA05ADDRHISNO DESC
                            """)                           
                        df_jusho = pd.read_sql(jusho_sql, conn, params={"jkinno": target_id})
    
                    if not df_jusho.empty:
                        st.dataframe(
                            df_jusho,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "履歴番号": st.column_config.NumberColumn(width="small"),
                                "郵便番号": st.column_config.TextColumn(width="small"),
                                "住所": st.column_config.TextColumn(width="large"),
                                "確認日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                "状態": st.column_config.TextColumn(width="small"),
                            }
                        )
                    else:
                        st.caption("住所履歴の登録はありません。")
    
                with st.expander("📛 氏名履歴", expanded=True):
                    with engine.connect() as conn:
                        name_his_sql = sqlalchemy.text("""
                            SELECT 
                                DA03NMHISNO as 履歴番号,
                                DA03NMUPDYD as 改姓名日,
                                (COALESCE(DA03FNMKJ, '') || ' ' || COALESCE(DA03LNMKJ, '')) as 氏名_漢字,
                                (COALESCE(DA03FNMSKJ, '') || ' ' || COALESCE(DA03LNMSKJ, '')) as 氏名_簡漢字,
                                (COALESCE(DA03FNMKN, '') || ' ' || COALESCE(DA03LNMKN, '')) as 氏名_カナ,
                                (COALESCE(DA03FNMALP, '') || ' ' || COALESCE(DA03LNMALP, '')) as 氏名_英字,
                                DA03NMHISNOTE as 備考
                            FROM d.da03
                            WHERE da03jkinno = :jkinno
                            ORDER BY DA03NMHISNO DESC
                        """)
                        df_name_his = pd.read_sql(name_his_sql, conn, params={"jkinno": target_id})
                    
                    if not df_name_his.empty:
                        st.dataframe(
                            df_name_his,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "履歴番号": st.column_config.NumberColumn(width="small"),
                                "改姓名日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                "氏名_漢字": st.column_config.TextColumn(width="medium"),
                                "氏名_簡漢字": st.column_config.TextColumn(width="medium"),
                                "氏名_カナ": st.column_config.TextColumn(width="medium"),
                                "氏名_英字": st.column_config.TextColumn(width="medium"),
                            }
                        )
                    else:
                        st.caption("氏名履歴の登録はありません。")
                
                with st.expander("📝 氏名補足履歴", expanded=False):
                    with engine.connect() as conn:
                        name_sub_sql = sqlalchemy.text("""
                            SELECT 
                                DA02NMSUBNO as 履歴番号,
                                CASE 
                                    WHEN da02nmtpcd = '10' THEN '別氏名'
                                    WHEN da02nmtpcd = '20' THEN '芸名'
                                    WHEN da02nmtpcd = '30' THEN 'ペン・ネーム'
                                    ELSE 'その他氏名' 
                                END as 種類,
                                (COALESCE(DA02FNMKJ, '') || ' ' || COALESCE(DA02LNMKJ, '')) as 氏名_漢字,
                                (COALESCE(DA02FNMSKJ, '') || ' ' || COALESCE(DA02LNMSKJ, '')) as 氏名_簡漢字,
                                (COALESCE(DA02FNMKN, '') || ' ' || COALESCE(DA02LNMKN, '')) as 氏名_カナ,
                                (COALESCE(DA02FNMALP, '') || ' ' || COALESCE(DA02LNMALP, '')) as 氏名_英字,
                                DA02NMSUBNOTE as 備考
                            FROM d.da02
                            WHERE da02jkinno = :jkinno
                            ORDER BY DA02NMSUBNO DESC
                        """)
                        df_name_sub = pd.read_sql(name_sub_sql, conn, params={"jkinno": target_id})
                    
                    if not df_name_sub.empty:
                        st.dataframe(
                            df_name_sub,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "履歴番号": st.column_config.NumberColumn(width="small"),
                                "種類": st.column_config.TextColumn(width="small"),
                                "氏名_漢字": st.column_config.TextColumn(width="medium"),
                                "氏名_簡漢字": st.column_config.TextColumn(width="medium"),
                                "氏名_カナ": st.column_config.TextColumn(width="medium"),
                                "氏名_英字": st.column_config.TextColumn(width="medium"),
                            }
                        )
                    else:
                        st.caption("氏名補足履歴の登録はありません。")

                if choice == "🔍 塾員検索（詳細）":                
                    with st.expander("🏛️ 公職", expanded=True):
                        with engine.connect() as conn:
                            job_his_sql = sqlalchemy.text("""
                                SELECT 
                                    DA09JKINNO as 塾員番号,
                                    DA09PBJOBNO as 情報番号,
                                    DA09PBJOBFG as 有効フラグ,
                                    DA09PBJOBNM as 塾員公職,
                                    DA09PBJOBBGNYD as 任期開始年月日,
                                    DA09PBJOBENDYD as 任期終了年月日,
                                    DA09PBJOBNOTE as 情報備考,
                                    DA09OPCD as 公開コード,
                                    DA09GETCD as 入手経路コード,
                                    DA09LASTUPDUSRID as 最終更新ユーザーＩＤ,
                                    DA09TIMESTAMP as タイムスタンプ
                                FROM D.DA09
                                WHERE DA09JKINNO = :jkinno
                                ORDER BY DA09PBJOBNO DESC
                            """)
                            df_job_his = pd.read_sql(job_his_sql, conn, params={"jkinno": target_id})
                    
                        if not df_job_his.empty:
                            st.dataframe(
                                df_job_his,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "塾員番号": None,  # 画面に重複して出す必要がなければ非表示
                                    "情報番号": st.column_config.NumberColumn(width="small"),
                                    "有効フラグ": st.column_config.TextColumn(width="small"), # '1'などが入るならCheckboxもあり
                                    "塾員公職": st.column_config.TextColumn(width="medium"),
                                    "任期開始年月日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                    "任期終了年月日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                    "情報備考": st.column_config.TextColumn(width="large"),
                                    "公開コード": st.column_config.TextColumn(width="small"),
                                    "入手経路コード": st.column_config.TextColumn(width="small"),
                                    "最終更新ユーザーＩＤ": None,  # 必要に応じて表示
                                    "タイムスタンプ": None,       # 必要に応じて表示
                                }
                            )
                        else:
                            st.caption("公職情報の登録はありません。")
    
    
                    with st.expander("🎖️ 叙位叙勲", expanded=True):
                        with engine.connect() as conn:
                            honors_sql = sqlalchemy.text("""
                                SELECT 
                                    DA08JKINNO as 塾員番号,
                                    DA08CFMCDNO as 情報番号,
                                    DA08CFMCDNM as 塾員叙位・叙勲,
                                    DA08CFMCDYD as 年月日,
                                    DA08CFMCDNOTE as 情報備考,
                                    DA08OPCD as 公開コード,
                                    DA08GETCD as 塾員情報入手経路コード,
                                    DA08LASTUPDUSRID as 最終更新ユーザーＩＤ,
                                    DA08TIMESTAMP as タイムスタンプ
                                FROM D.DA08
                                WHERE DA08JKINNO = :jkinno
                                ORDER BY DA08CFMCDNO DESC
                            """)
                            df_honors = pd.read_sql(honors_sql, conn, params={"jkinno": target_id})
                    
                        if not df_honors.empty:
                            st.dataframe(
                                df_honors,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "塾員番号": None,  # 非表示
                                    "情報番号": st.column_config.NumberColumn(width="small"),
                                    "塾員叙位・叙勲": st.column_config.TextColumn(width="medium"),
                                    "年月日": st.column_config.DateColumn(format="YYYY/MM/DD"),
                                    "情報備考": st.column_config.TextColumn(width="large"),
                                    "公開コード": st.column_config.TextColumn(width="small"),
                                    "塾員情報入手経路コード": st.column_config.TextColumn(width="small"),
                                    "最終更新ユーザーＩＤ": None,
                                    "タイムスタンプ": None,
                                }
                            )
                        else:
                            st.caption("叙位叙勲情報の登録はありません。")
                            
    

                    
            


# --- B.  操作ログ閲覧 ---
elif choice == "📋 操作ログ閲覧":
    st.subheader("同部署IDでの操作履歴")
    st.info("直近の検索および詳細閲覧のログを表示しています。")

    try:
        with engine.connect() as conn:
            # ログ取得用SQL（ご提示のものを流用）
            log_sql = sqlalchemy.text("""
                SELECT
                    dl01timestamp as 操作日付,
                    dl01formid as 画面ID,
                    dl01function as 機能ID,
                    dl01count as 表示件数,
                    dl01jkinno as 塾員ID_検索,
                    dl01searchtext as あいまい検索テキスト,
                    dl01fnm as 氏_検索,
                    dl01lnm as 名_検索,
                    dl01birth as 誕生日_検索,
                    dl01sgrad as 卒年_MIN_検索,
                    dl01egrad as 卒年_MAX_検索,
                    dl01pcuser as 個人ID,
                    dl01appid as ログインID
                FROM d.dl01
                WHERE dl01appid = :Appid
                ORDER BY dl01timestamp DESC
                LIMIT 100
            """)

            # ログイン中のIDで絞り込み
            params = {"Appid": current_user}
            
            result = conn.execute(log_sql, params)
            log_df = pd.DataFrame(result.fetchall(), columns=result.keys())

        if not log_df.empty:
            # 操作日付を読みやすくフォーマット（必要に応じて）
            log_df['操作日付'] = pd.to_datetime(log_df['操作日付']).dt.strftime('%Y-%m-%d %H:%M:%S')

            st.dataframe(
                log_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "操作日付": st.column_config.TextColumn("操作日時", width="medium"),
                    "画面ID": st.column_config.TextColumn("画面", width="small"),
                    "表示件数": st.column_config.NumberColumn("件数"),
                }
            )
        else:
            st.warning("操作ログが見つかりませんでした。")

    except Exception as e:
        st.error(f"ログの取得中にエラーが発生しました: {e}")                    
                    
# --- B. SFDC同期状態確認 ---
elif choice == "📊 SFDC同期状態確認":
    st.title("📊 SFDC同期状態確認")
    if st.button("最新の情報に更新"): st.rerun()
    try:
        with engine.connect() as conn:
            df = pd.read_sql(sqlalchemy.text("SELECT * FROM d.get_sync_status()"), conn)
            st.dataframe(df, use_container_width=True, height=800)
    except Exception as e:
        st.error(f"エラー: {e}")

# --- C. パスワード変更 ---
elif choice == "🔑 パスワード変更":
    st.title("🔑 パスワード変更")
    st.info("セキュリティのため、ランダムに生成されたパスワードへの変更のみ可能です。")

    # 1. パスワード生成ボタン（フォームの外に配置して生成値を保持）
    if st.button("ランダムパスワードを生成"):
        st.session_state.pw_val = generate_pass()
    
    generated_pw = st.session_state.get("pw_val", "")
    if generated_pw:
        st.code(f"新しいパスワード: {generated_pw}", language="")
        st.warning("このパスワードは画面をリロードすると消えるため、必ずメモしてください。")

    # 2. パスワード変更フォーム
    with st.form("upd_form"):
        st.write(f"実行ユーザー: **{current_user}**")
        old_pw = st.text_input("現在のパスワード", type="password")
        
        # 表示のみ行い、ユーザーによる編集を不可（または無視）にする
        st.text_input("新パスワード", value=generated_pw, disabled=True)
        
        submit = st.form_submit_button("更新実行")

        if submit:
            if not generated_pw:
                st.error("先に「ランダムパスワードを生成」ボタンを押してください。")
            else:
                try:
                    with engine.connect() as conn:
                        # 1. まずSELECTでパスワードを確認（ここはトランザクション不要でもOK）
                        sql_check = sqlalchemy.text("SELECT xc04applusrpwd FROM x.xc04 WHERE xc04applusrid = :id")
                        stored_hash = conn.execute(sql_check, {"id": current_user}).scalar()
                    
                        if stored_hash and des_crypt.verify(old_pw, stored_hash.strip()):
                            # 2. 一致した時だけ begin を呼んで更新する
                            with conn.begin():
                                conn.execute(
                                    sqlalchemy.text("CALL x.update_user_proc(:id, :pw, :admin)"),
                                    {"id": current_user, "pw": hash_password(generated_pw), "admin": current_user}
                                )
                            st.success("パスワードを更新しました。")
                        # 完了後に生成値をクリア
                        if "pw_val" in st.session_state:
                            del st.session_state.pw_val
                        else:
                            st.error("現在のパスワードが正しくありません。")
                
                except Exception as e:
                    st.error(f"エラーが発生しました: {e}")

# --- D. 新規ユーザー作成 ---
elif choice == "👤 新規ユーザー作成":
    st.title("👤 新規ユーザー作成")
    if st.button("パスワード生成"): st.session_state.pw_add = generate_pass()
    with st.form("add_form"):
        uid = st.text_input("新規ID")
        upw = st.text_input("初期パスワード", value=st.session_state.get("pw_add", ""))
        if st.form_submit_button("作成"):
            with engine.connect() as conn:
                conn.execute(sqlalchemy.text("CALL x.create_user_proc(:id, :pw, :admin)"),
                             {"id":uid, "pw":hash_password(upw), "admin":current_user})
                conn.commit()
            st.success("作成完了")

# ==========================================
# 6. 各機能の表示ロジック
# ==========================================

# --- 新規追加：塾員照会 (生年月日検索) ---
# --- 新規追加：塾員照会 (生年月日検索) ---
elif choice == "🎓 塾員照会 (メディア用)":
    st.title("🎓 塾員照会 (メディア用)")
    st.markdown("メディア検索用：姓・名・生年月日の組み合わせで照会します。")

    with st.form("simple_lookup_form"):
        st.markdown("### 📋 照会条件")
        c1, c2, c3 = st.columns(3)
        
        # ユーザー指定の3項目
        fnm_input = c1.text_input("姓 (漢字/カナ)")
        lnm_input = c2.text_input("名 (漢字/カナ)")
        birth_input = c3.text_input("生年月日 (YYYY-MM-DD)")

        st.divider()
        submit_btn = st.form_submit_button("🔍 照会実行", type="primary", use_container_width=True)

    if submit_btn:
        # 生年月日と氏名(姓または名)が入力されているかチェック
        if (fnm_input or lnm_input) and birth_input:
            with st.spinner("照会中..."):
                try:
                    # SQLパラメータの構築
                    # 指定された3項目以外は空文字やデフォルト値をセット
                    params = {
                        "Jkinno": "",
                        "SearchText": fnm_input or "",
                        "SearchText2": lnm_input or "",
                        "SearchText3": "",
                        "FNM": "",
                        "LNM": "",
                        "Birth": birth_input or "",
                        "SGrad": -1,
                        "EGrad": -1,
                        "Pcuser": st.session_state.username,
                        "Appid": "STREAMLIT",
                        "FormId": "SIMPLE_LOOKUP", # 識別用
                        "Pcname": "CloudRun",
                        "FCd": "",
                        "Bukkoflg": True
                    }

                    sql = sqlalchemy.text("""
                        SELECT 
                            jkinno AS "塾員番号", 
                            nmkj AS "氏名", 
                            nmkn AS "カナ", 
                            birthyd AS "生年月日",
                            da06gradyynm as 卒年,
                            da06keioscnm as "学校・学部",
                            da06classnm as "学科・専攻"
                        FROM d.da_guest_serch_web(
                            :Jkinno, :SearchText, :SearchText2, :SearchText3, 
                            :FNM, :LNM, :Birth, :SGrad, :EGrad, 
                            :Pcuser, :Appid, :FormId, :Pcname, :FCd, :Bukkoflg
                        ) LEFT OUTER JOIN d.da06
                           ON da06jkinno = jkinno
                        ORDER BY jkinno,da06sccareerno desc
                    """)

                    with engine.connect() as conn:
                        df_result = pd.read_sql(sql, conn, params=params)

                    if not df_result.empty:
                        st.success(f"✅ {len(df_result)} 件見つかりました。")
                        st.dataframe(df_result, use_container_width=True, hide_index=True,
                            column_config={
                                "塾員番号": st.column_config.TextColumn(width="small"),
                                "氏名": st.column_config.TextColumn(width="medium"),
                                "カナ": st.column_config.TextColumn(width="medium"),
                                "生年月日": st.column_config.TextColumn(width="medium"),
                                "学校・学部": st.column_config.TextColumn(width="medium"),
                                "学科・専攻": st.column_config.TextColumn(width="medium"),
                            }
                        )
                    else:
                        st.warning("該当する情報が見つかりませんでした。")
                
                except Exception as e:
                    st.error(f"エラーが発生しました: {e}")
        else:
            st.error("⚠️ 氏名(姓または名)と生年月日の両方を入力してください。")
    # ...送信処理...
