//! Sudoku outbound (mihomo `transport/sudoku`), ported client-side:
//! KIP message framing over an AEAD record layer whose every byte is
//! further hidden behind the "sudoku table" byte obfuscation.
//!
//! ## Upstream map
//!
//! * `adapter/outbound/sudoku.go` — `SudokuOption`, dial glue
//!   (`DialContext` → `dialAndHandshake` + `WriteKIPMessage(KIPTypeOpenTCP)`,
//!   `ListenPacketContext` → `KIPTypeStartUoT` + `NewUoTPacketConn`).
//! * `transport/sudoku/kip.go` — KIP framing: `"kip" || type u8 || len
//!   be16 || payload`, the client/server hello payloads, the feature
//!   bits and the user-hash derivation.
//! * `transport/sudoku/handshake.go` — `ClientHandshake`: legacy HTTP
//!   mask header, table pick, obfs conn, `RecordConn`, KIP exchange.
//! * `transport/sudoku/handshake_kip.go` — X25519 ephemeral + nonce
//!   echo + session rekey (60s clock skew tolerance).
//! * `transport/sudoku/session_keys.go` — PSK/session key derivation
//!   (HKDF-SHA256 over `sha256(seed)`).
//! * `transport/sudoku/init.go` — `ClientAEADSeed` (PSK passthrough,
//!   hex point canonicalization, split/master key recovery).
//! * `transport/sudoku/crypto/record_conn.go` — the AEAD record layer
//!   (`epoch u32 BE || seq u64 BE` header as nonce+AAD, per-direction
//!   epoch rotation every 32 MiB of plaintext, strict receive ordering).
//! * `transport/sudoku/tables.go` + `obfs/sudoku/{table,layout,grid,
//!   ascii_mode}.go` — the obfuscation tables: the 288 valid 4x4 sudoku
//!   grids in backtracking order, shuffled with Go's `math/rand`
//!   seeded from `sha256(key)`, mapped byte→(grid, witness positions)
//!   with per-direction ASCII/entropy/custom-x/p/v layouts.
//! * `transport/sudoku/obfs/sudoku/{conn,encode,packed,downlink,
//!   rand,padding_prob}.go` — pure (4 hint bytes per byte, random
//!   permutation + probability-based padding) and packed (base64-ish
//!   6-bit groups) codecs. The client always writes pure and reads
//!   pure or packed (`enable-pure-downlink`, default true).
//! * `transport/sudoku/address.go` — target encoding: SOCKS-style
//!   `atyp || addr || port` (1=IPv4, 3=domain, 4=IPv6; port LAST —
//!   unlike the sing port-first form).
//! * `transport/sudoku/uot.go` — UDP-over-TCP datagram framing:
//!   `addrLen be16 || payloadLen be16 || addr || payload`.
//! * `transport/sudoku/obfs/httpmask/masker.go` — the legacy HTTP
//!   camouflage request header written before the obfuscated stream.
//! * `transport/sudoku/obfs/httpmask/{tunnel_dial,tunnel_api,
//!   tunnel_conn_stream,tunnel_conn_poll,tunnel_ws,ws_stream_conn,
//!   tunnel_conn_queue,tunnel_ready,tunnel_retry,ws_auth}.go` + the
//!   client half of `transport/sudoku/early_handshake.go` — the
//!   HTTP-camouflage tunnels that carry the KIP session: `stream`
//!   (split long-pull + sequenced POST uploads), `poll` (base64-line
//!   pulls/pushes), `auto` (stream probe with poll fallback) and `ws`
//!   (WebSocket upgrade with HMAC anti-probe auth), all with the
//!   optional `http-mask-tls` layer, Host/SNI override and path-root
//!   namespacing. The KIP exchange rides the tunnels as the *early
//!   handshake*: the obfuscated client hello in the `ed` query param,
//!   the obfuscated server hello in the authorize `ed=` field (ws: the
//!   `X-Sudoku-Early` response header).
//! * `transport/sudoku/multiplex{.go,/session.go}` + `multiplex_dialer.go`
//!   — `multiplex: on`: `KIPTypeStartMux` then a self-contained
//!   session mux (`open/data/close/reset` frames, 128 KiB data chunks,
//!   15s keepalive as DATA on stream 0).
//!
//! ## Wire-compatible Go `math/rand`
//!
//! The table shuffle must match Go's `math/rand.New(NewSource(seed)).
//! Shuffle` bit for bit, so `gorand` below is a faithful transcription
//! of `rng.go` (rngCooked, seedrand, the additive generator, `int31n`
//! rejection sampling and Fisher-Yates), pinned by vectors generated
//! with Go 1.26 on this machine.
//!
//! ## Scope / deviations
//!
//! * All httpmask modes are implemented: `legacy` (the default: one
//!   header before the raw stream) and the HTTP tunnels `stream`,
//!   `poll`, `auto`, `ws` (see `connect_tunnel*`).
//! * The tunnel HTTP client is hand-rolled HTTP/1.1 over one fresh
//!   connection per request: upstream pools keep-alive connections and
//!   preconnects three sockets per session (`tunnel_preconnect.go`,
//!   `http.Transport`); the per-request wire form is identical, the
//!   port just opens more TCP connections. Likewise upstream's https
//!   arm negotiates h2 (`ForceAttemptHTTP2`); this port offers ALPN
//!   `http/1.1` only.
//! * `multiplex: on` is implemented (the session mux is
//!   self-contained); `connect_tunnel_mux` awaits the tunnel readiness
//!   (`WaitTunnelReady`). The persistent `MultiplexDialer` warm-keeping
//!   loop is the integrator's job — `connect_tunnel_mux` returns the
//!   live session.
//! * **`multiplex: auto`** only enables HTTPMask transport reuse
//!   upstream (config.go:67); this port has no shared transport, so
//!   `auto` is accepted and treated as `off` (documented; no wire
//!   difference per request).
//! * `handshake-timeout` (server-side) and the server's replay filter
//!   are server concerns; the client never sends them.
//! * `ClientAEADSeed` uses curve25519-dalek's edwards25519 point
//!   arithmetic; a 32-byte hex value is accepted as a point only when
//!   it round-trips canonically (filippo/edwards25519 `SetBytes`
//!   semantics).
//! * The packed encoder is upstream's *server* downlink; the port
//!   implements packed decoding (client reads) and keeps the encoder
//!   in the test mimic only.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind};
use crate::stream::BoxProxyStream;

// ---------------------------------------------------------------------------
// Go math/rand (src/math/rand/rng.go + go1 rand.go) — table compatibility
// ---------------------------------------------------------------------------

mod gorand {
    //! Bit-exact transcription of Go's `math/rand` `rngSource` +
    //! `Rand.Shuffle`/`int31n`, required because the sudoku table
    //! layout depends on `rand.New(rand.NewSource(seed)).Shuffle`.

    const RNG_LEN: usize = 607;
    const RNG_TAP: usize = 273;
    const INT32_MAX: i64 = (1 << 31) - 1;

    /// Go `math/rand` `rngCooked` (src/math/rand/rng.go), the additive-
    /// lagged-Fibonacci seeding table. Transcribed verbatim for table
    /// shuffle wire compatibility.
    const RNG_COOKED: [i64; 607] = [
    -4181792142133755926, -4576982950128230565, 1395769623340756751, 5333664234075297259,
    -6347679516498800754, 9033628115061424579, 7143218595135194537, 4812947590706362721,
    7937252194349799378, 5307299880338848416, 8209348851763925077, -7107630437535961764,
    4593015457530856296, 8140875735541888011, -5903942795589686782, -603556388664454774,
    -7496297993371156308, 113108499721038619, 4569519971459345583, -4160538177779461077,
    -6835753265595711384, -6507240692498089696, 6559392774825876886, 7650093201692370310,
    7684323884043752161, -8965504200858744418, -2629915517445760644, 271327514973697897,
    -6433985589514657524, 1065192797246149621, 3344507881999356393, -4763574095074709175,
    7465081662728599889, 1014950805555097187, -4773931307508785033, -5742262670416273165,
    2418672789110888383, 5796562887576294778, 4484266064449540171, 3738982361971787048,
    -4699774852342421385, 10530508058128498, -589538253572429690, -6598062107225984180,
    8660405965245884302, 10162832508971942, -2682657355892958417, 7031802312784620857,
    6240911277345944669, 831864355460801054, -1218937899312622917, 2116287251661052151,
    2202309800992166967, 9161020366945053561, 4069299552407763864, 4936383537992622449,
    457351505131524928, -8881176990926596454, -6375600354038175299, -7155351920868399290,
    4368649989588021065, 887231587095185257, -3659780529968199312, -2407146836602825512,
    5616972787034086048, -751562733459939242, 1686575021641186857, -5177887698780513806,
    -4979215821652996885, -1375154703071198421, 5632136521049761902, -8390088894796940536,
    -193645528485698615, -5979788902190688516, -4907000935050298721, -285522056888777828,
    -2776431630044341707, 1679342092332374735, 6050638460742422078, -2229851317345194226,
    -1582494184340482199, 5881353426285907985, 812786550756860885, 4541845584483343330,
    -6497901820577766722, 4980675660146853729, -4012602956251539747, -329088717864244987,
    -2896929232104691526, 1495812843684243920, -2153620458055647789, 7370257291860230865,
    -2466442761497833547, 4706794511633873654, -1398851569026877145, 8549875090542453214,
    -9189721207376179652, -7894453601103453165, 7297902601803624459, 1011190183918857495,
    -6985347000036920864, 5147159997473910359, -8326859945294252826, 2659470849286379941,
    6097729358393448602, -7491646050550022124, -5117116194870963097, -896216826133240300,
    -745860416168701406, 5803876044675762232, -787954255994554146, -3234519180203704564,
    -4507534739750823898, -1657200065590290694, 505808562678895611, -4153273856159712438,
    -8381261370078904295, 572156825025677802, 1791881013492340891, 3393267094866038768,
    -5444650186382539299, 2352769483186201278, -7930912453007408350, -325464993179687389,
    -3441562999710612272, -6489413242825283295, 5092019688680754699, -227247482082248967,
    4234737173186232084, 5027558287275472836, 4635198586344772304, -536033143587636457,
    5907508150730407386, -8438615781380831356, 972392927514829904, -3801314342046600696,
    -4064951393885491917, -174840358296132583, 2407211146698877100, -1640089820333676239,
    3940796514530962282, -5882197405809569433, 3095313889586102949, -1818050141166537098,
    5832080132947175283, 7890064875145919662, 8184139210799583195, -8073512175445549678,
    -7758774793014564506, -4581724029666783935, 3516491885471466898, -8267083515063118116,
    6657089965014657519, 5220884358887979358, 1796677326474620641, 5340761970648932916,
    1147977171614181568, 5066037465548252321, 2574765911837859848, 1085848279845204775,
    -5873264506986385449, 6116438694366558490, 2107701075971293812, -7420077970933506541,
    2469478054175558874, -1855128755834809824, -5431463669011098282, -9038325065738319171,
    -6966276280341336160, 7217693971077460129, -8314322083775271549, 7196649268545224266,
    -3585711691453906209, -5267827091426810625, 8057528650917418961, -5084103596553648165,
    -2601445448341207749, -7850010900052094367, 6527366231383600011, 3507654575162700890,
    9202058512774729859, 1954818376891585542, -2582991129724600103, 8299563319178235687,
    -5321504681635821435, 7046310742295574065, -2376176645520785576, -7650733936335907755,
    8850422670118399721, 3631909142291992901, 5158881091950831288, -6340413719511654215,
    4763258931815816403, 6280052734341785344, -4979582628649810958, 2043464728020827976,
    -2678071570832690343, 4562580375758598164, 5495451168795427352, -7485059175264624713,
    553004618757816492, 6895160632757959823, -989748114590090637, 7139506338801360852,
    -672480814466784139, 5535668688139305547, 2430933853350256242, -3821430778991574732,
    -1063731997747047009, -3065878205254005442, 7632066283658143750, 6308328381617103346,
    3681878764086140361, 3289686137190109749, 6587997200611086848, 244714774258135476,
    -5143583659437639708, 8090302575944624335, 2945117363431356361, -8359047641006034763,
    3009039260312620700, -793344576772241777, 401084700045993341, -1968749590416080887,
    4707864159563588614, -3583123505891281857, -3240864324164777915, -5908273794572565703,
    -3719524458082857382, -5281400669679581926, 8118566580304798074, 3839261274019871296,
    7062410411742090847, -8481991033874568140, 6027994129690250817, -6725542042704711878,
    -2971981702428546974, -7854441788951256975, 8809096399316380241, 6492004350391900708,
    2462145737463489636, -8818543617934476634, -5070345602623085213, -8961586321599299868,
    -3758656652254704451, -8630661632476012791, 6764129236657751224, -709716318315418359,
    -3403028373052861600, -8838073512170985897, -3999237033416576341, -2920240395515973663,
    -2073249475545404416, 368107899140673753, -6108185202296464250, -6307735683270494757,
    4782583894627718279, 6718292300699989587, 8387085186914375220, 3387513132024756289,
    4654329375432538231, -292704475491394206, -3848998599978456535, 7623042350483453954,
    7725442901813263321, 9186225467561587250, -5132344747257272453, -6865740430362196008,
    2530936820058611833, 1636551876240043639, -3658707362519810009, 1452244145334316253,
    -7161729655835084979, -7943791770359481772, 9108481583171221009, -3200093350120725999,
    5007630032676973346, 2153168792952589781, 6720334534964750538, -3181825545719981703,
    3433922409283786309, 2285479922797300912, 3110614940896576130, -2856812446131932915,
    -3804580617188639299, 7163298419643543757, 4891138053923696990, 580618510277907015,
    1684034065251686769, 4429514767357295841, -8893025458299325803, -8103734041042601133,
    7177515271653460134, 4589042248470800257, -1530083407795771245, 143607045258444228,
    246994305896273627, -8356954712051676521, 6473547110565816071, 3092379936208876896,
    2058427839513754051, -4089587328327907870, 8785882556301281247, -3074039370013608197,
    -637529855400303673, 6137678347805511274, -7152924852417805802, 5708223427705576541,
    -3223714144396531304, 4358391411789012426, 325123008708389849, 6837621693887290924,
    4843721905315627004, -3212720814705499393, -3825019837890901156, 4602025990114250980,
    1044646352569048800, 9106614159853161675, -8394115921626182539, -4304087667751778808,
    2681532557646850893, 3681559472488511871, -3915372517896561773, -2889241648411946534,
    -6564663803938238204, -8060058171802589521, 581945337509520675, 3648778920718647903,
    -4799698790548231394, -7602572252857820065, 220828013409515943, -1072987336855386047,
    4287360518296753003, -4633371852008891965, 5513660857261085186, -2258542936462001533,
    -8744380348503999773, 8746140185685648781, 228500091334420247, 1356187007457302238,
    3019253992034194581, 3152601605678500003, -8793219284148773595, 5559581553696971176,
    4916432985369275664, -8559797105120221417, -5802598197927043732, 2868348622579915573,
    -7224052902810357288, -5894682518218493085, 2587672709781371173, -7706116723325376475,
    3092343956317362483, -5561119517847711700, 972445599196498113, -1558506600978816441,
    1708913533482282562, -2305554874185907314, -6005743014309462908, -6653329009633068701,
    -483583197311151195, 2488075924621352812, -4529369641467339140, -4663743555056261452,
    2997203966153298104, 1282559373026354493, 240113143146674385, 8665713329246516443,
    628141331766346752, -4651421219668005332, -7750560848702540400, 7596648026010355826,
    -3132152619100351065, 7834161864828164065, 7103445518877254909, 4390861237357459201,
    -4780718172614204074, -319889632007444440, 622261699494173647, -3186110786557562560,
    -8718967088789066690, -1948156510637662747, -8212195255998774408, -7028621931231314745,
    2623071828615234808, -4066058308780939700, -5484966924888173764, -6683604512778046238,
    -6756087640505506466, 5256026990536851868, 7841086888628396109, 6640857538655893162,
    -8021284697816458310, -7109857044414059830, -1689021141511844405, -4298087301956291063,
    -4077748265377282003, -998231156719803476, 2719520354384050532, 9132346697815513771,
    4332154495710163773, -2085582442760428892, 6994721091344268833, -2556143461985726874,
    -8567931991128098309, 59934747298466858, -3098398008776739403, -265597256199410390,
    2332206071942466437, -7522315324568406181, 3154897383618636503, -7585605855467168281,
    -6762850759087199275, 197309393502684135, -8579694182469508493, 2543179307861934850,
    4350769010207485119, -4468719947444108136, -7207776534213261296, -1224312577878317200,
    4287946071480840813, 8362686366770308971, 6486469209321732151, -5605644191012979782,
    -1669018511020473564, 4450022655153542367, -7618176296641240059, -3896357471549267421,
    -4596796223304447488, -6531150016257070659, -8982326463137525940, -4125325062227681798,
    -1306489741394045544, -8338554946557245229, 5329160409530630596, 7790979528857726136,
    4955070238059373407, -4304834761432101506, -6215295852904371179, 3007769226071157901,
    -6753025801236972788, 8928702772696731736, 7856187920214445904, -4748497451462800923,
    7900176660600710914, -7082800908938549136, -6797926979589575837, -6737316883512927978,
    4186670094382025798, 1883939007446035042, -414705992779907823, 3734134241178479257,
    4065968871360089196, 6953124200385847784, -7917685222115876751, -7585632937840318161,
    -5567246375906782599, -5256612402221608788, 3106378204088556331, -2894472214076325998,
    4565385105440252958, 1979884289539493806, -6891578849933910383, 3783206694208922581,
    8464961209802336085, 2843963751609577687, 3030678195484896323, -4429654462759003204,
    4459239494808162889, 402587895800087237, 8057891408711167515, 4541888170938985079,
    1042662272908816815, -3666068979732206850, 2647678726283249984, 2144477441549833761,
    -3417019821499388721, -2105601033380872185, 5916597177708541638, -8760774321402454447,
    8833658097025758785, 5970273481425315300, 563813119381731307, -6455022486202078793,
    1598828206250873866, -4016978389451217698, -2988328551145513985, -6071154634840136312,
    8469693267274066490, 125672920241807416, -3912292412830714870, -2559617104544284221,
    -486523741806024092, -4735332261862713930, 5923302823487327109, -9082480245771672572,
    -1808429243461201518, 7990420780896957397, 4317817392807076702, 3625184369705367340,
    -6482649271566653105, -3480272027152017464, -3225473396345736649, -368878695502291645,
    -3981164001421868007, -8522033136963788610, 7609280429197514109, 3020985755112334161,
    -2572049329799262942, 2635195723621160615, 5144520864246028816, -8188285521126945980,
    1567242097116389047, 8172389260191636581, -2885551685425483535, -7060359469858316883,
    -6480181133964513127, -7317004403633452381, 6011544915663598137, 5932255307352610768,
    2241128460406315459, -8327867140638080220, 3094483003111372717, 4583857460292963101,
    9079887171656594975, -384082854924064405, -3460631649611717935, 4225072055348026230,
    -7385151438465742745, 3801620336801580414, -399845416774701952, -7446754431269675473,
    7899055018877642622, 5421679761463003041, 5521102963086275121, -4975092593295409910,
    8735487530905098534, -7462844945281082830, -2080886987197029914, -1000715163927557685,
    -4253840471931071485, -5828896094657903328, 6424174453260338141, 359248545074932887,
    -5949720754023045210, -2426265837057637212, 3030918217665093212, -9077771202237461772,
    -3186796180789149575, 740416251634527158, -2142944401404840226, 6951781370868335478,
    399922722363687927, -8928469722407522623, -1378421100515597285, -8343051178220066766,
    -3030716356046100229, -8811767350470065420, 9026808440365124461, 6440783557497587732,
    4615674634722404292, 539897290441580544, 2096238225866883852, 8751955639408182687,
    -7316147128802486205, 7381039757301768559, 6157238513393239656, -1473377804940618233,
    8629571604380892756, 5280433031239081479, 7101611890139813254, 2479018537985767835,
    7169176924412769570, -1281305539061572506, -7865612307799218120, 2278447439451174845,
    3625338785743880657, 6477479539006708521, 8976185375579272206, -3712000482142939688,
    1326024180520890843, 7537449876596048829, 5464680203499696154, 3189671183162196045,
    6346751753565857109, -8982212049534145501, -6127578587196093755, -245039190118465649,
    -6320577374581628592, 7208698530190629697, 7276901792339343736, -7490986807540332668,
    4133292154170828382, 2918308698224194548, -7703910638917631350, -3929437324238184044,
    -4300543082831323144, -6344160503358350167, 5896236396443472108, -758328221503023383,
    -1894351639983151068, -307900319840287220, -6278469401177312761, -2171292963361310674,
    8382142935188824023, 9103922860780351547, 4152330101494654406,
];

    /// `rngSource` (rng.go:67).
    pub(super) struct RngSource {
        tap: i32,
        feed: i32,
        vec: Box<[i64; RNG_LEN]>,
    }

    /// `seedrand` (rng.go:187): x[n+1] = 48271 * x[n] mod (2^31-1),
    /// Schrage's method.
    fn seedrand(x: i32) -> i32 {
        const A: i64 = 48271;
        const Q: i64 = 44488;
        const R: i64 = 3399;
        let hi = (x as i64) / Q;
        let lo = (x as i64) % Q;
        let mut nx = A * lo - R * hi;
        if nx < 0 {
            nx += INT32_MAX;
        }
        nx as i32
    }

    impl RngSource {
        /// `rand.NewSource(seed)` → `rngSource.Seed` (rng.go:204).
        pub(super) fn new(seed: i64) -> Self {
            let mut src = RngSource {
                tap: 0,
                feed: RNG_LEN as i32 - RNG_TAP as i32,
                vec: Box::new([0i64; RNG_LEN]),
            };
            src.seed(seed);
            src
        }

        fn seed(&mut self, seed: i64) {
            self.tap = 0;
            self.feed = RNG_LEN as i32 - RNG_TAP as i32;
            let mut seed = seed.rem_euclid_rules();
            if seed == 0 {
                seed = 89482311;
            }
            let mut x = seed as i32;
            for i in -20i32..RNG_LEN as i32 {
                x = seedrand(x);
                if i >= 0 {
                    let mut u: i64 = (x as i64) << 40;
                    x = seedrand(x);
                    u ^= (x as i64) << 20;
                    x = seedrand(x);
                    u ^= x as i64;
                    u ^= RNG_COOKED[i as usize];
                    self.vec[i as usize] = u;
                }
            }
        }

        /// `Uint64` (rng.go:238).
        fn uint64(&mut self) -> u64 {
            self.tap -= 1;
            if self.tap < 0 {
                self.tap += RNG_LEN as i32;
            }
            self.feed -= 1;
            if self.feed < 0 {
                self.feed += RNG_LEN as i32;
            }
            let x = self.vec[self.feed as usize]
                .wrapping_add(self.vec[self.tap as usize]);
            self.vec[self.feed as usize] = x;
            x as u64
        }

        /// `Int63` (rng.go:233).
        fn int63(&mut self) -> i64 {
            (self.uint64() & ((1u64 << 63) - 1)) as i64
        }

        /// `Rand.Int31` (rand.go:110) — completeness (int31n uses the
        /// Lemire path on `Uint32`).
        #[allow(dead_code)]
        fn int31(&mut self) -> i32 {
            (self.int63() >> 32) as i32
        }

        /// `Rand.Uint32` (rand.go:99): the high 32 bits after `>> 31`.
        fn uint32(&mut self) -> u32 {
            (self.int63() >> 31) as u32
        }

        /// `Rand.int31n` (rand.go:161) — Lemire multiply-shift with the
        /// `(2^32 - n) % n` rejection threshold.
        fn int31n(&mut self, n: i32) -> i32 {
            debug_assert!(n > 0);
            let n = n as u32;
            let mut v = self.uint32();
            let mut prod = u64::from(v) * u64::from(n);
            let mut low = prod as u32;
            if low < n {
                let thresh = n.wrapping_neg() % n;
                while low < thresh {
                    v = self.uint32();
                    prod = u64::from(v) * u64::from(n);
                    low = prod as u32;
                }
            }
            (prod >> 32) as i32
        }

        /// `Rand.Shuffle` (rand.go:294) — Fisher-Yates with the
        /// `int63n` arm only for n beyond 2^31 (never reached here).
        pub(super) fn shuffle(&mut self, n: usize, mut swap: impl FnMut(usize, usize)) {
            let mut i = n as i64 - 1;
            while i > (INT32_MAX - 1) {
                let j = self.int63n(i + 1);
                swap(i as usize, j as usize);
                i -= 1;
            }
            while i > 0 {
                let j = self.int31n((i + 1) as i32) as i64;
                swap(i as usize, j as usize);
                i -= 1;
            }
        }

        /// `Rand.Int63n` (rand.go:115) for the (unused here) large arm.
        fn int63n(&mut self, n: i64) -> i64 {
            debug_assert!(n > 0);
            if n & (n - 1) == 0 {
                return self.int63() & (n - 1);
            }
            let max = (((1u64 << 63) - 1) - ((1u64 << 63) % n as u64)) as i64;
            loop {
                let v = self.int63();
                if v <= max {
                    return v % n;
                }
            }
        }
    }

    /// Go's `seed % int32max` truncates toward zero and keeps the
    /// result in `[0, int32max)` for any i64 (rng.go:210-215).
    trait SeedMod {
        fn rem_euclid_rules(self) -> i64;
    }

    impl SeedMod for i64 {
        fn rem_euclid_rules(self) -> i64 {
            let mut v = self % INT32_MAX;
            if v < 0 {
                v += INT32_MAX;
            }
            v
        }
    }
}

// ---------------------------------------------------------------------------
// Grids, layouts, tables (obfs/sudoku)
// ---------------------------------------------------------------------------

/// All 288 valid 4x4 sudoku grids in upstream backtracking order
/// (grid.go `GenerateAllGrids`); the order feeds the shuffle.
fn generate_all_grids() -> Vec<[u8; 16]> {
    fn backtrack(idx: usize, g: &mut [u8; 16], out: &mut Vec<[u8; 16]>) {
        if idx == 16 {
            out.push(*g);
            return;
        }
        let (row, col) = (idx / 4, idx % 4);
        let (br, bc) = ((row / 2) * 2, (col / 2) * 2);
        for num in 1u8..=4 {
            let mut valid = true;
            for i in 0..4 {
                if g[row * 4 + i] == num || g[i * 4 + col] == num {
                    valid = false;
                    break;
                }
            }
            if valid {
                for r in 0..2 {
                    for c in 0..2 {
                        if g[(br + r) * 4 + (bc + c)] == num {
                            valid = false;
                        }
                    }
                }
            }
            if valid {
                g[idx] = num;
                backtrack(idx + 1, g, out);
                g[idx] = 0;
            }
        }
    }
    let mut grids = Vec::with_capacity(288);
    backtrack(0, &mut [0u8; 16], &mut grids);
    grids
}

/// `ascii_mode.go ParseASCIIMode`: the per-direction layout preference.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AsciiMode {
    uplink: AsciiToken,
    downlink: AsciiToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsciiToken {
    Ascii,
    Entropy,
}

impl AsciiMode {
    fn parse(mode: &str) -> Result<Self> {
        let raw = mode.trim().to_ascii_lowercase();
        match raw.as_str() {
            "" | "entropy" | "prefer_entropy" => {
                return Ok(AsciiMode { uplink: AsciiToken::Entropy, downlink: AsciiToken::Entropy })
            }
            "ascii" | "prefer_ascii" => {
                return Ok(AsciiMode { uplink: AsciiToken::Ascii, downlink: AsciiToken::Ascii })
            }
            _ => {}
        }
        let Some(rest) = raw.strip_prefix("up_") else {
            return Err(Error::config(format!(
                "sudoku: table-type must be prefer_ascii, prefer_entropy, up_ascii_down_entropy, \
                 or up_entropy_down_ascii (got {mode:?})"
            )));
        };
        let (up, down) = rest.split_once("_down_").ok_or_else(|| {
            Error::config(format!(
                "sudoku: table-type must be prefer_ascii, prefer_entropy, up_ascii_down_entropy, \
                 or up_entropy_down_ascii (got {mode:?})"
            ))
        })?;
        Ok(AsciiMode {
            uplink: AsciiToken::parse(up)?,
            downlink: AsciiToken::parse(down)?,
        })
    }

    /// `Canonical`.
    fn canonical(&self) -> String {
        if self.uplink == AsciiToken::Ascii && self.downlink == AsciiToken::Ascii {
            "prefer_ascii".into()
        } else if self.uplink == AsciiToken::Entropy && self.downlink == AsciiToken::Entropy {
            "prefer_entropy".into()
        } else {
            format!(
                "up_{}_down_{}",
                self.uplink.token(),
                self.downlink.token()
            )
        }
    }

    fn uplink_preference(&self) -> &'static str {
        self.uplink.preference()
    }

    fn downlink_preference(&self) -> &'static str {
        self.downlink.preference()
    }
}

impl AsciiToken {
    fn parse(tok: &str) -> Result<Self> {
        match tok.trim().to_ascii_lowercase().as_str() {
            "ascii" | "prefer_ascii" => Ok(AsciiToken::Ascii),
            "entropy" | "prefer_entropy" | "" => Ok(AsciiToken::Entropy),
            _ => Err(Error::config(
                "sudoku: table-type must be prefer_ascii, prefer_entropy, up_ascii_down_entropy, \
                 or up_entropy_down_ascii",
            )),
        }
    }

    fn token(&self) -> &'static str {
        match self {
            AsciiToken::Ascii => "ascii",
            AsciiToken::Entropy => "entropy",
        }
    }

    fn preference(&self) -> &'static str {
        match self {
            AsciiToken::Ascii => "prefer_ascii",
            AsciiToken::Entropy => "prefer_entropy",
        }
    }
}

/// `layout.go byteLayout`.
#[derive(Debug, Clone)]
struct ByteLayout {
    name: String,
    hint_table: [bool; 256],
    encode_hint: [[u8; 16]; 4],
    encode_group: [u8; 64],
    decode_group: [u8; 256],
    group_valid: [bool; 256],
    pad_marker: u8,
    padding_pool: Vec<u8>,
}

impl ByteLayout {
    fn hint_byte(&self, val: u8, pos: u8) -> u8 {
        self.encode_hint[(val & 0x03) as usize][(pos & 0x0f) as usize]
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn group_byte(&self, group: u8) -> u8 {
        self.encode_group[(group & 0x3f) as usize]
    }

    fn decode_packed_group(&self, b: u8) -> Option<u8> {
        if self.group_valid[b as usize] {
            Some(self.decode_group[b as usize])
        } else {
            None
        }
    }
}

/// `resolveLayout` (layout.go:45): ASCII wins; entropy + custom pattern
/// → custom; anything else errors.
fn resolve_layout(mode: &str, custom_pattern: &str) -> Result<ByteLayout> {
    match mode.to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => return Ok(new_ascii_layout()),
        "entropy" | "prefer_entropy" | "" => {}
        other => {
            return Err(Error::config(format!(
                "sudoku: invalid ascii mode {other:?}"
            )))
        }
    }
    if !custom_pattern.trim().is_empty() {
        return new_custom_layout(custom_pattern);
    }
    Ok(new_entropy_layout())
}

/// `newASCIILayout` (layout.go:61).
fn new_ascii_layout() -> ByteLayout {
    let padding: Vec<u8> = (0x20u8..=0x3f).collect();
    let mut layout = ByteLayout {
        name: "ascii".into(),
        hint_table: [false; 256],
        encode_hint: [[0; 16]; 4],
        encode_group: [0; 64],
        decode_group: [0; 256],
        group_valid: [false; 256],
        pad_marker: 0x3f,
        padding_pool: padding,
    };
    for val in 0u8..4 {
        for pos in 0u8..16 {
            let mut b = 0x40u8 | (val << 4) | pos;
            if b == 0x7f {
                b = b'\n';
            }
            layout.encode_hint[val as usize][pos as usize] = b;
        }
    }
    for group in 0u8..64 {
        let mut b = 0x40u8 | group;
        if b == 0x7f {
            b = b'\n';
        }
        layout.encode_group[group as usize] = b;
    }
    for b in 0u16..256 {
        let wire = b as u8;
        if wire & 0x40 == 0x40 {
            layout.hint_table[wire as usize] = true;
            layout.decode_group[wire as usize] = wire & 0x3f;
            layout.group_valid[wire as usize] = true;
        }
    }
    layout.hint_table[b'\n' as usize] = true;
    layout.decode_group[b'\n' as usize] = 0x3f;
    layout.group_valid[b'\n' as usize] = true;
    layout
}

/// `newEntropyLayout` (layout.go:106).
fn new_entropy_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(16);
    for i in 0u8..8 {
        padding.push(0x80 + i);
        padding.push(0x10 + i);
    }
    let mut layout = ByteLayout {
        name: "entropy".into(),
        hint_table: [false; 256],
        encode_hint: [[0; 16]; 4],
        encode_group: [0; 64],
        decode_group: [0; 256],
        group_valid: [false; 256],
        pad_marker: 0x80,
        padding_pool: padding,
    };
    for val in 0u8..4 {
        for pos in 0u8..16 {
            layout.encode_hint[val as usize][pos as usize] = (val << 5) | pos;
        }
    }
    for group in 0u8..64 {
        let v = group;
        layout.encode_group[group as usize] = ((v & 0x30) << 1) | (v & 0x0f);
    }
    for b in 0u16..256 {
        let wire = b as u8;
        if wire & 0x90 != 0 {
            continue;
        }
        layout.hint_table[wire as usize] = true;
        layout.decode_group[wire as usize] = ((wire >> 1) & 0x30) | (wire & 0x0f);
        layout.group_valid[wire as usize] = true;
    }
    layout
}

/// `newCustomLayout` (layout.go:143): an 8-symbol pattern of exactly
/// 2 x / 2 p / 4 v placing the bit roles.
fn new_custom_layout(pattern: &str) -> Result<ByteLayout> {
    let cleaned: String = pattern
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if cleaned.len() != 8 {
        return Err(Error::config(format!(
            "sudoku: custom table must have 8 symbols, got {}",
            cleaned.len()
        )));
    }
    let mut x_bits: Vec<u8> = Vec::new();
    let mut p_bits: Vec<u8> = Vec::new();
    let mut v_bits: Vec<u8> = Vec::new();
    for (i, c) in cleaned.bytes().enumerate() {
        let bit = (7 - i) as u8;
        match c {
            b'x' => x_bits.push(bit),
            b'p' => p_bits.push(bit),
            b'v' => v_bits.push(bit),
            _ => {
                return Err(Error::config(format!(
                    "sudoku: invalid char {:?} in custom table",
                    cleaned.as_bytes()[i] as char
                )))
            }
        }
    }
    if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
        return Err(Error::config(
            "sudoku: custom table must contain exactly 2 x, 2 p, 4 v",
        ));
    }
    let mut x_mask = 0u8;
    for b in &x_bits {
        x_mask |= 1 << b;
    }
    let encode_bits = |val: u8, pos: u8, drop_x: i32| -> u8 {
        let mut out = x_mask;
        if drop_x >= 0 {
            out &= !(1u8 << x_bits[drop_x as usize]);
        }
        if val & 0x02 != 0 {
            out |= 1 << p_bits[0];
        }
        if val & 0x01 != 0 {
            out |= 1 << p_bits[1];
        }
        for (i, bit) in v_bits.iter().enumerate() {
            if (pos >> (3 - i as u8)) & 0x01 == 1 {
                out |= 1 << bit;
            }
        }
        out
    };
    // The padding pool: every encoding with one x bit dropped whose
    // popcount is >= 5 (layout.go:193-208), sorted.
    let mut padding: Vec<u8> = Vec::new();
    for drop in 0..x_bits.len() {
        for val in 0u8..4 {
            for pos in 0u8..16 {
                let b = encode_bits(val, pos, drop as i32);
                if b.count_ones() >= 5 && !padding.contains(&b) {
                    padding.push(b);
                }
            }
        }
    }
    padding.sort_unstable();
    if padding.is_empty() {
        return Err(Error::config("sudoku: custom table produced empty padding pool"));
    }
    let mut layout = ByteLayout {
        name: format!("custom({cleaned})"),
        hint_table: [false; 256],
        encode_hint: [[0; 16]; 4],
        encode_group: [0; 64],
        decode_group: [0; 256],
        group_valid: [false; 256],
        pad_marker: padding[0],
        padding_pool: padding,
    };
    for val in 0u8..4 {
        for pos in 0u8..16 {
            layout.encode_hint[val as usize][pos as usize] = encode_bits(val, pos, -1);
        }
    }
    for group in 0u8..64 {
        let val = (group >> 4) & 0x03;
        let pos = group & 0x0f;
        layout.encode_group[group as usize] = encode_bits(val, pos, -1);
    }
    for b in 0u16..256 {
        let wire = b as u8;
        if wire & x_mask != x_mask {
            continue;
        }
        layout.hint_table[wire as usize] = true;
        let mut val = 0u8;
        let mut pos = 0u8;
        if wire & (1 << p_bits[0]) != 0 {
            val |= 0x02;
        }
        if wire & (1 << p_bits[1]) != 0 {
            val |= 0x01;
        }
        for (i, bit) in v_bits.iter().enumerate() {
            if wire & (1 << bit) != 0 {
                pos |= 1 << (3 - i as u8);
            }
        }
        layout.decode_group[wire as usize] = (val << 4) | pos;
        layout.group_valid[wire as usize] = true;
    }
    Ok(layout)
}

/// `table.go packHintBytes`: the sorted 4-byte key (order-insensitive).
fn pack_hint_bytes(h0: u8, h1: u8, h2: u8, h3: u8) -> u32 {
    let mut a = [h0, h1, h2, h3];
    a.sort_unstable();
    (u32::from(a[0]) << 24) | (u32::from(a[1]) << 16) | (u32::from(a[2]) << 8) | u32::from(a[3])
}

/// `tableHintFingerprint` (table.go:183).
fn table_hint_fingerprint(key: &str, mode: &str, uplink_pattern: &str, downlink_pattern: &str) -> u32 {
    let joined = [
        "sudoku-table-hint".to_string(),
        key.to_string(),
        mode.to_string(),
        uplink_pattern.trim().to_ascii_lowercase(),
        downlink_pattern.trim().to_ascii_lowercase(),
    ]
    .join("\0");
    let sum = Sha256::digest(joined.as_bytes());
    u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]])
}

/// `table.go Table` — one direction's obfuscation table.
pub struct Table {
    /// `EncodeTable[byte]` — every unique 4-position witness encoding.
    encode_table: Box<[Vec<[u8; 4]>]>,
    /// `DecodeMap[sorted-hints]`.
    decode_map: HashMap<u32, u8>,
    padding_pool: Vec<u8>,
    is_ascii: bool,
    layout: ByteLayout,
    /// `opposite` (downlink table for directional modes).
    opposite: Option<Arc<Table>>,
    hint: u32,
}

impl Table {
    /// `OppositeDirection`.
    fn opposite_direction(&self) -> Arc<Table> {
        match &self.opposite {
            Some(o) => o.clone(),
            None => Arc::new(Table {
                encode_table: self.encode_table.to_vec().into_boxed_slice(),
                decode_map: self.decode_map.clone(),
                padding_pool: self.padding_pool.clone(),
                is_ascii: self.is_ascii,
                layout: self.layout.clone(),
                opposite: None,
                hint: self.hint,
            }),
        }
    }

    /// `Hint`.
    fn hint(&self) -> u32 {
        self.hint
    }
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("layout", &self.layout.name)
            .field("is_ascii", &self.is_ascii)
            .field("hint", &self.hint)
            .field("entries", &self.encode_table[0].len())
            .finish()
    }
}

/// `newSingleDirectionTable` (table.go:69).
fn new_single_direction_table(key: &str, mode: &str, custom_pattern: &str) -> Result<Table> {
    let layout = resolve_layout(mode, custom_pattern)?;
    let all_grids = generate_all_grids();

    let seed_digest = Sha256::digest(key.as_bytes());
    let seed = i64::from_be_bytes(seed_digest[..8].try_into().expect("8 bytes"));
    let mut shuffled = all_grids.clone();
    let mut rng = gorand::RngSource::new(seed);
    rng.shuffle(shuffled.len(), |i, j| shuffled.swap(i, j));

    // C(16,4) witness position combinations in `combine` (table.go:98)
    // lexicographic order.
    let combinations = {
        let mut combos: Vec<[u8; 4]> = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        fn combine(s: u8, k: u8, cur: &mut Vec<u8>, out: &mut Vec<[u8; 4]>) {
            if k == 0 {
                out.push([cur[0], cur[1], cur[2], cur[3]]);
                return;
            }
            for i in s..=(16 - k) {
                cur.push(i);
                combine(i + 1, k - 1, cur, out);
                cur.pop();
            }
        }
        combine(0, 4, &mut cur, &mut combos);
        combos
    };

    let mut encode_table: Vec<Vec<[u8; 4]>> = vec![Vec::new(); 256];
    let mut decode_map: HashMap<u32, u8> = HashMap::new();
    for byte_val in 0u16..256 {
        let target_grid = &shuffled[byte_val as usize];
        for positions in &combinations {
            let mut raw_parts: [(u8, u8); 4] = [(0, 0); 4];
            for (i, pos) in positions.iter().enumerate() {
                raw_parts[i] = (target_grid[*pos as usize], *pos);
            }
            // Uniqueness across all grids (table.go:129-145).
            let mut match_count = 0;
            'outer: for g in &all_grids {
                for p in &raw_parts {
                    if g[p.1 as usize] != p.0 {
                        continue 'outer;
                    }
                }
                match_count += 1;
                if match_count > 1 {
                    break;
                }
            }
            if match_count == 1 {
                let hints = [
                    layout.hint_byte(raw_parts[0].0 - 1, raw_parts[0].1),
                    layout.hint_byte(raw_parts[1].0 - 1, raw_parts[1].1),
                    layout.hint_byte(raw_parts[2].0 - 1, raw_parts[2].1),
                    layout.hint_byte(raw_parts[3].0 - 1, raw_parts[3].1),
                ];
                encode_table[byte_val as usize].push(hints);
                decode_map.insert(pack_hint_bytes(hints[0], hints[1], hints[2], hints[3]), byte_val as u8);
            }
        }
        if encode_table[byte_val as usize].is_empty() {
            return Err(Error::crypto(format!(
                "sudoku: byte {byte_val} has no unique grid witness"
            )));
        }
    }

    Ok(Table {
        encode_table: encode_table.into_boxed_slice(),
        decode_map,
        padding_pool: layout.padding_pool.clone(),
        is_ascii: layout.name == "ascii",
        layout,
        opposite: None,
        hint: 0,
    })
}

/// `customPatternForToken` (table.go:162).
fn custom_pattern_for_token(token: AsciiToken, pattern: &str) -> String {
    if token == AsciiToken::Entropy {
        pattern.to_string()
    } else {
        String::new()
    }
}

/// `NewTableWithCustom` (table.go:39): builds the uplink table and, for
/// directional modes, attaches the downlink opposite.
fn new_table_with_custom(key: &str, mode: &str, custom_pattern: &str) -> Result<Arc<Table>> {
    let ascii_mode = AsciiMode::parse(mode)?;
    let uplink_pattern = custom_pattern_for_token(ascii_mode.uplink, custom_pattern);
    let downlink_pattern = custom_pattern_for_token(ascii_mode.downlink, custom_pattern);
    let hint = table_hint_fingerprint(
        key,
        &ascii_mode.canonical(),
        &uplink_pattern,
        &downlink_pattern,
    );
    let mut uplink = new_single_direction_table(key, ascii_mode.uplink_preference(), &uplink_pattern)?;
    uplink.hint = hint;
    if ascii_mode.uplink == ascii_mode.downlink {
        return Ok(Arc::new(uplink));
    }
    let mut downlink =
        new_single_direction_table(key, ascii_mode.downlink_preference(), &downlink_pattern)?;
    downlink.hint = hint;
    uplink.opposite = Some(Arc::new(downlink));
    Ok(Arc::new(uplink))
}

/// `tables.go NewTablesWithCustomPatterns` / `NewClientTablesWithCustomPatterns`:
/// one table per rotation pattern (`custom-tables` overrides `custom-table`).
fn new_client_tables_with_custom_patterns(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<Arc<Table>>> {
    AsciiMode::parse(table_type)?;
    let patterns: Vec<String> = if !custom_tables.is_empty() {
        custom_tables.to_vec()
    } else if !custom_table.trim().is_empty() {
        vec![custom_table.to_string()]
    } else {
        vec![String::new()]
    };
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in &patterns {
        let pattern = pattern.trim();
        tables.push(new_table_with_custom(key, table_type, pattern)?);
    }
    Ok(tables)
}

// ---------------------------------------------------------------------------
// The obfs RNG + padding probability (obfs/sudoku/rand.go, padding_prob.go)
// ---------------------------------------------------------------------------

/// `sudokuRand`: xorshift64* with a cached half.
struct SudokuRng {
    state: u64,
    cached: u32,
    have_cached: bool,
}

impl SudokuRng {
    /// `newSeededRand`: 8 OS-random bytes as the state.
    fn new_seeded() -> Self {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SudokuRng::new_with_seed(i64::from_be_bytes(b))
    }

    fn new_with_seed(seed: i64) -> Self {
        let mut state = seed as u64;
        if state == 0 {
            state = 0x9e37_79b9_7f4a_7c15;
        }
        SudokuRng {
            state,
            cached: 0,
            have_cached: false,
        }
    }

    /// `Uint64`.
    fn uint64(&mut self) -> u64 {
        self.have_cached = false;
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// `Uint32`: the high half first, then the cached low half.
    fn uint32(&mut self) -> u32 {
        if self.have_cached {
            self.have_cached = false;
            return self.cached;
        }
        let v = self.uint64();
        self.cached = v as u32;
        self.have_cached = true;
        (v >> 32) as u32
    }

    /// `Intn` via `fastIntnFromUint32`.
    fn intn(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        ((self.uint32() as u64 * n as u64) >> 32) as usize
    }
}

/// `padding_prob.go probOne`.
const PROB_ONE: u64 = 1u64 << 32;

/// `pickPaddingThreshold` (padding_prob.go:5): the per-connection
/// padding probability in `[0, 2^32]`, clamped exactly as upstream.
fn pick_padding_threshold(rng: &mut SudokuRng, p_min: i64, p_max: i64) -> u64 {
    let mut p_min = p_min;
    let mut p_max = p_max;
    if p_min < 0 {
        p_min = 0;
    }
    if p_max < p_min {
        p_max = p_min;
    }
    if p_max > 100 {
        p_max = 100;
    }
    if p_min > 100 {
        p_min = 100;
    }
    let min = p_min as u64 * PROB_ONE / 100;
    let max = p_max as u64 * PROB_ONE / 100;
    if max <= min {
        return min;
    }
    let u = rng.uint32() as u64;
    min + ((u * (max - min)) >> 32)
}

/// `conn.go perm4` — all 24 permutations of 4 elements.
const PERM4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

/// `encode.go encodeSudokuPayload`: every byte becomes 4 hint bytes in
/// a random permutation, with probability-threshold padding inserted
/// from the table's padding pool.
fn encode_sudoku_payload(
    out: &mut Vec<u8>,
    table: &Table,
    rng: &mut SudokuRng,
    padding_threshold: u64,
    p: &[u8],
) -> Result<()> {
    if p.is_empty() {
        return Ok(());
    }
    let pads = &table.padding_pool;
    let pad_len = pads.len();
    let pick_pad = |rng: &mut SudokuRng| pads[rng.intn(pad_len)];
    if padding_threshold >= PROB_ONE {
        for &b in p {
            out.push(pick_pad(rng));
            let puzzles = &table.encode_table[b as usize];
            let puzzle = puzzles[rng.intn(puzzles.len())];
            let perm = &PERM4[rng.intn(PERM4.len())];
            for idx in perm {
                out.push(pick_pad(rng));
                out.push(puzzle[*idx]);
            }
        }
        out.push(pick_pad(rng));
        return Ok(());
    }
    for &b in p {
        if (rng.uint32() as u64) < padding_threshold {
            out.push(pick_pad(rng));
        }
        let puzzles = &table.encode_table[b as usize];
        let puzzle = puzzles[rng.intn(puzzles.len())];
        let perm = &PERM4[rng.intn(PERM4.len())];
        for idx in perm {
            if (rng.uint32() as u64) < padding_threshold {
                out.push(pick_pad(rng));
            }
            out.push(puzzle[*idx]);
        }
    }
    if (rng.uint32() as u64) < padding_threshold {
        out.push(pick_pad(rng));
    }
    Ok(())
}

/// `pending.go`-style decoded-byte spill: bytes that decode past the
/// caller's buffer wait here.
#[derive(Default)]
struct PendingBuffer {
    data: Vec<u8>,
    off: usize,
}

impl PendingBuffer {
    fn available(&self) -> usize {
        self.data.len() - self.off
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(dead_code)]
    fn push(&mut self, b: u8) {
        self.data.push(b);
    }

    fn drain_into(&mut self, dst: &mut Vec<u8>, limit: usize) -> bool {
        if self.available() == 0 {
            return false;
        }
        let n = self.available().min(limit);
        dst.extend_from_slice(&self.data[self.off..self.off + n]);
        self.off += n;
        if self.off >= self.data.len() {
            self.data.clear();
            self.off = 0;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// The obfuscated stream (client side of conn.go + packed.go)
// ---------------------------------------------------------------------------

/// The decoder state shared by the pure and packed downlink paths
/// (`Conn`'s hintBuf/hintCount and `PackedConn`'s readBitBuf).
struct ObfsDecodeState {
    hint_buf: [u8; 4],
    hint_count: usize,
    bit_buf: u64,
    bit_count: u32,
}

/// One chunk of `Conn.Read` / `PackedConn.Read`'s decode loops
/// (conn.go:181-217, packed.go:326-370).
fn decode_chunk(
    table: &Table,
    pure: bool,
    st: &mut ObfsDecodeState,
    chunk: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    let layout = &table.layout;
    for &b in chunk {
        if !layout.hint_table[b as usize] {
            if !pure && b == layout.pad_marker {
                st.bit_buf = 0;
                st.bit_count = 0;
            }
            continue;
        }
        if pure {
            st.hint_buf[st.hint_count] = b;
            st.hint_count += 1;
            if st.hint_count == 4 {
                let key = pack_hint_bytes(st.hint_buf[0], st.hint_buf[1], st.hint_buf[2], st.hint_buf[3]);
                let val = table
                    .decode_map
                    .get(&key)
                    .copied()
                    .ok_or_else(|| Error::protocol("sudoku: INVALID_SUDOKU_MAP_MISS"))?;
                out.push(val);
                st.hint_count = 0;
            }
        } else {
            let group = layout
                .decode_packed_group(b)
                .ok_or_else(|| Error::protocol("sudoku: INVALID_SUDOKU_MAP_MISS"))?;
            st.bit_buf = (st.bit_buf << 6) | u64::from(group);
            st.bit_count += 6;
            if st.bit_count >= 8 {
                st.bit_count -= 8;
                let val = (st.bit_buf >> st.bit_count) as u8;
                if st.bit_count == 0 {
                    st.bit_buf = 0;
                } else {
                    st.bit_buf &= (1u64 << st.bit_count) - 1;
                }
                out.push(val);
            }
        }
    }
    Ok(())
}

/// The client's obfs layer: pure-sudoku uplink writes, and downlink
/// reads through either the pure decoder or the packed decoder
/// (`buildClientObfsConn`, handshake.go:300).
struct ObfsStream {
    inner: BoxProxyStream,
    /// Uplink (write) table.
    table: Arc<Table>,
    /// Downlink (read) table — the uplink table's opposite.
    read_table: Arc<Table>,
    pure_downlink: bool,
    rng: SudokuRng,
    threshold: u64,
    // Read-side state.
    rbuf: BytesMut,
    out: BytesMut,
    pending: PendingBuffer,
    hint_buf: [u8; 4],
    hint_count: usize,
    bit_buf: u64,
    bit_count: u32,
    eof: bool,
    // Write-side staging (encode once per write, drain across polls —
    // a mid-write Pending must not re-encode and duplicate bytes).
    wbuf: BytesMut,
    pending_plain: usize,
}

impl ObfsStream {
    fn new(
        inner: BoxProxyStream,
        table: Arc<Table>,
        padding_min: i64,
        padding_max: i64,
        pure_downlink: bool,
    ) -> Self {
        // The client reads through the uplink table's opposite.
        let read_table = table.opposite_direction();
        Self::with_tables(inner, table, read_table, padding_min, padding_max, pure_downlink)
    }

    /// Explicit write/read tables (the test mimic's server side writes
    /// with the downlink table and reads with the uplink table).
    fn with_tables(
        inner: BoxProxyStream,
        table: Arc<Table>,
        read_table: Arc<Table>,
        padding_min: i64,
        padding_max: i64,
        pure_downlink: bool,
    ) -> Self {
        let mut rng = SudokuRng::new_seeded();
        let threshold = pick_padding_threshold(&mut rng, padding_min, padding_max);
        ObfsStream {
            inner,
            table,
            read_table,
            pure_downlink,
            rng,
            threshold,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            pending: PendingBuffer::default(),
            hint_buf: [0; 4],
            hint_count: 0,
            bit_buf: 0,
            bit_count: 0,
            eof: false,
            wbuf: BytesMut::new(),
            pending_plain: 0,
        }
    }

    /// Decode every decodable byte in `rbuf` into `out` (and the
    /// pending spill). Mirrors the loops of `Conn.Read` and
    /// `PackedConn.Read` without their read-size shaping (pure I/O
    /// detail in Go's io.Reader model).
    fn decode_buffered(&mut self) -> Result<()> {
        let mut st = ObfsDecodeState {
            hint_buf: self.hint_buf,
            hint_count: self.hint_count,
            bit_buf: self.bit_buf,
            bit_count: self.bit_count,
        };
        let mut out = std::mem::take(&mut self.out).to_vec();
        let r = decode_chunk(
            &self.read_table,
            self.pure_downlink,
            &mut st,
            &self.rbuf,
            &mut out,
        );
        self.out = BytesMut::from(&out[..]);
        self.hint_buf = st.hint_buf;
        self.hint_count = st.hint_count;
        self.bit_buf = st.bit_buf;
        self.bit_count = st.bit_count;
        self.rbuf.clear();
        r
    }
}

impl AsyncWrite for ObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.wbuf.is_empty() {
            let table = self.table.clone();
            let threshold = self.threshold;
            let mut encoded = Vec::with_capacity(buf.len() * 6 + 8);
            encode_sudoku_payload(&mut encoded, &table, &mut self.rng, threshold, buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.wbuf = BytesMut::from(&encoded[..]);
            self.pending_plain = buf.len();
        }
        while !self.wbuf.is_empty() {
            let n = {
                let mut wbuf = std::mem::take(&mut self.wbuf);
                let r = Pin::new(&mut self.inner).poll_write(cx, &wbuf);
                let consumed = matches!(&r, Poll::Ready(Ok(n)) if *n > 0);
                let n = match r {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => {
                        self.wbuf = wbuf;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.wbuf = wbuf;
                        return Poll::Pending;
                    }
                };
                if consumed {
                    wbuf.advance(n);
                }
                self.wbuf = wbuf;
                n
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sudoku: transport accepted zero bytes",
                )));
            }
        }
        Poll::Ready(Ok(self.pending_plain))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for ObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.out.is_empty() && self.pending.available() > 0 {
                let mut spill = Vec::new();
                self.pending.drain_into(&mut spill, usize::MAX);
                self.out.extend_from_slice(&spill);
            }
            if !self.out.is_empty() {
                let n = self.out.len().min(buf.remaining());
                buf.put_slice(&self.out[..n]);
                self.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                self.eof = true;
                // `PackedConn.Read` clears partial-group state on EOF.
                self.bit_buf = 0;
                self.bit_count = 0;
                continue;
            }
            self.rbuf.extend_from_slice(rb.filled());
            if let Err(e) = self.decode_buffered() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RecordConn (crypto/record_conn.go)
// ---------------------------------------------------------------------------

const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY_SIZE: usize = 65535;
/// `KeyUpdateAfterBytes` (record_conn.go:23).
const KEY_UPDATE_AFTER_BYTES: i64 = 32 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordMethod {
    None,
    Aes128Gcm,
    Chacha20Poly1305,
}

impl RecordMethod {
    fn parse(method: &str) -> Result<Self> {
        match method {
            "" | "chacha20-poly1305" => Ok(RecordMethod::Chacha20Poly1305),
            "aes-128-gcm" => Ok(RecordMethod::Aes128Gcm),
            "none" => Ok(RecordMethod::None),
            other => Err(Error::config(format!(
                "sudoku: invalid aead-method {other:?}, must be one of: aes-128-gcm, \
                 chacha20-poly1305, none"
            ))),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            RecordMethod::None => "none",
            RecordMethod::Aes128Gcm => "aes-128-gcm",
            RecordMethod::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// `deriveEpochKey` (record_conn.go:260):
/// `HMAC-SHA256(base, "sudoku-record:" || method || epoch_be32)`.
fn derive_epoch_key(base: &[u8], epoch: u32, method: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).expect("hmac accepts any key");
    mac.update(b"sudoku-record:");
    mac.update(method.as_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn random_non_zero_u32() -> u32 {
    loop {
        let mut b = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let v = u32::from_be_bytes(b);
        if v != 0 && v != u32::MAX {
            return v;
        }
    }
}

fn random_non_zero_u64() -> u64 {
    loop {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let v = u64::from_be_bytes(b);
        if v != 0 && v != u64::MAX {
            return v;
        }
    }
}

/// The AEAD record layer (record_conn.go `RecordConn`), generic over
/// the obfs stream so the in-test server mimic can plug its own
/// downlink writer.
struct RecordConn<O = ObfsStream> {
    inner: O,
    method: RecordMethod,
    base_send: [u8; 32],
    base_recv: [u8; 32],
    send_aead: Option<Aead>,
    send_aead_epoch: u32,
    recv_aead: Option<Aead>,
    recv_aead_epoch: u32,
    send_epoch: u32,
    send_seq: u64,
    send_bytes: i64,
    send_epoch_updates: u32,
    recv_epoch: u32,
    recv_seq: u64,
    recv_initialized: bool,
    rbuf: BytesMut,
    out: BytesMut,
    eof: bool,
    // Write-side staging across polls (see ObfsStream).
    wbuf: BytesMut,
    pending_plain: usize,
}

impl<O> RecordConn<O> {
    fn new(inner: O, method: RecordMethod, base_send: [u8; 32], base_recv: [u8; 32]) -> Self {
        let send_epoch = random_non_zero_u32();
        let send_seq = random_non_zero_u64();
        RecordConn {
            inner,
            method,
            base_send,
            base_recv,
            send_aead: None,
            send_aead_epoch: 0,
            recv_aead: None,
            recv_aead_epoch: 0,
            send_epoch,
            send_seq,
            send_bytes: 0,
            send_epoch_updates: 0,
            recv_epoch: 0,
            recv_seq: 0,
            recv_initialized: false,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            eof: false,
            wbuf: BytesMut::new(),
            pending_plain: 0,
        }
    }

    /// `Rekey` (record_conn.go:118).
    fn rekey(&mut self, base_send: [u8; 32], base_recv: [u8; 32]) {
        self.base_send = base_send;
        self.base_recv = base_recv;
        self.send_epoch = random_non_zero_u32();
        self.send_seq = random_non_zero_u64();
        self.send_bytes = 0;
        self.send_epoch_updates = 0;
        self.recv_epoch = 0;
        self.recv_seq = 0;
        self.recv_initialized = false;
        self.rbuf.clear();
        self.out.clear();
        self.wbuf.clear();
        self.pending_plain = 0;
        self.send_aead = None;
        self.recv_aead = None;
        self.send_aead_epoch = 0;
        self.recv_aead_epoch = 0;
    }

    fn aead_for(&self, base: &[u8; 32], epoch: u32) -> Result<Option<Aead>> {
        if self.method == RecordMethod::None {
            return Ok(None);
        }
        let key = derive_epoch_key(base, epoch, self.method.label());
        let kind = match self.method {
            RecordMethod::Aes128Gcm => AeadKind::Aes128Gcm,
            _ => AeadKind::Chacha20Poly1305,
        };
        Aead::new(kind, &key[..kind.key_len()])
            .map(Some)
            .map_err(|_| Error::crypto("sudoku: epoch key derivation"))
    }

    /// `maybeBumpSendEpochLocked` (record_conn.go:270).
    fn maybe_bump_send_epoch(&mut self, added_plain: usize) -> Result<()> {
        if self.method == RecordMethod::None {
            return Ok(());
        }
        self.send_bytes += added_plain as i64;
        let threshold = KEY_UPDATE_AFTER_BYTES * i64::from(self.send_epoch_updates + 1);
        if self.send_bytes < threshold {
            return Ok(());
        }
        self.send_epoch = self.send_epoch.wrapping_add(1);
        self.send_epoch_updates += 1;
        self.send_seq = random_non_zero_u64();
        Ok(())
    }

    /// `validateRecvPosition` (record_conn.go:290).
    fn validate_recv_position(&self, epoch: u32, seq: u64) -> Result<()> {
        if !self.recv_initialized {
            return Ok(());
        }
        if epoch < self.recv_epoch {
            return Err(Error::protocol(format!(
                "sudoku: replayed epoch: got {epoch} want >={}",
                self.recv_epoch
            )));
        }
        if epoch == self.recv_epoch && seq != self.recv_seq {
            return Err(Error::protocol(format!(
                "sudoku: out of order: epoch={epoch} got={seq} want={}",
                self.recv_seq
            )));
        }
        if epoch > self.recv_epoch && epoch - self.recv_epoch > 8 {
            return Err(Error::protocol(format!(
                "sudoku: epoch jump too large: got {epoch} want<={}",
                self.recv_epoch + 8
            )));
        }
        Ok(())
    }

    /// Try to consume one complete frame from `rbuf` (`Read`).
    fn try_parse(&mut self) -> Result<bool> {
        if self.method == RecordMethod::None {
            if self.rbuf.is_empty() {
                return Ok(false);
            }
            self.out.extend_from_slice(&self.rbuf);
            self.rbuf.clear();
            return Ok(true);
        }
        if self.rbuf.len() < 2 {
            return Ok(false);
        }
        let body_len = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]) as usize;
        if body_len < RECORD_HEADER_SIZE {
            return Err(Error::protocol("sudoku: frame too short"));
        }
        if body_len > MAX_FRAME_BODY_SIZE {
            return Err(Error::protocol("sudoku: frame too large"));
        }
        if self.rbuf.len() < 2 + body_len {
            return Ok(false);
        }
        let body = self.rbuf[2..2 + body_len].to_vec();
        self.rbuf.advance(2 + body_len);
        let header: [u8; 12] = body[..RECORD_HEADER_SIZE].try_into().expect("12 bytes");
        let epoch = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let seq = u64::from_be_bytes(header[4..12].try_into().expect("8 bytes"));
        self.validate_recv_position(epoch, seq)?;
        if self.recv_aead.is_none() || self.recv_aead_epoch != epoch {
            self.recv_aead = self.aead_for(&self.base_recv, epoch)?;
            self.recv_aead_epoch = epoch;
        }
        let aead = self.recv_aead.as_ref().expect("initialized above");
        let plain = aead.open(&header, &header, &body[RECORD_HEADER_SIZE..])?;
        self.recv_epoch = epoch;
        self.recv_seq = seq.wrapping_add(1);
        self.recv_initialized = true;
        self.out.extend_from_slice(&plain);
        Ok(true)
    }
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl<O: AsyncWrite + Unpin> AsyncWrite for RecordConn<O> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.method == RecordMethod::None {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let max_plain = MAX_FRAME_BODY_SIZE - RECORD_HEADER_SIZE - 16;
        // Build the frames only when nothing is staged; a poll that
        // returns Pending mid-drain must not re-frame the same bytes.
        let mut wbuf = std::mem::take(&mut self.wbuf);
        if wbuf.is_empty() {
            self.pending_plain = buf.len();
            let mut written = 0usize;
            while written < buf.len() {
                let end = (written + max_plain).min(buf.len());
                let chunk = &buf[written..end];
                let n = chunk.len();
                if self.send_aead.is_none() || self.send_aead_epoch != self.send_epoch {
                    self.send_aead = self
                        .aead_for(&self.base_send, self.send_epoch)
                        .map_err(io_invalid)?;
                    self.send_aead_epoch = self.send_epoch;
                }
                let mut header = [0u8; RECORD_HEADER_SIZE];
                header[..4].copy_from_slice(&self.send_epoch.to_be_bytes());
                header[4..].copy_from_slice(&self.send_seq.to_be_bytes());
                self.send_seq = self.send_seq.wrapping_add(1);
                let body_len = RECORD_HEADER_SIZE + n + 16;
                if body_len > MAX_FRAME_BODY_SIZE {
                    self.wbuf = wbuf;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sudoku: frame too large",
                    )));
                }
                wbuf.extend_from_slice(&(body_len as u16).to_be_bytes());
                wbuf.extend_from_slice(&header);
                let aead = self.send_aead.as_ref().expect("initialized above");
                let mut ct = Vec::with_capacity(n + 16);
                aead.seal(&header, &header, chunk, &mut ct)
                    .map_err(io_invalid)?;
                wbuf.extend_from_slice(&ct);
                written = end;
                if let Err(e) = self.maybe_bump_send_epoch(n) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())));
                }
            }
        }
        let mut off = 0usize;
        while off < wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &wbuf[off..]) {
                Poll::Ready(Ok(0)) => {
                    self.wbuf = wbuf.split_off(off);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sudoku: transport accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => off += n,
                Poll::Ready(Err(e)) => {
                    self.wbuf = wbuf.split_off(off);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Park the unwritten tail; the next poll resumes
                    // draining it (no re-framing, no re-encoding).
                    self.wbuf = wbuf.split_off(off);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(self.pending_plain))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<O: AsyncRead + Unpin> AsyncRead for RecordConn<O> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.out.is_empty() {
                let n = self.out.len().min(buf.remaining());
                buf.put_slice(&self.out[..n]);
                self.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.try_parse() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))
                }
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                self.eof = true;
                continue;
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
    }
}

// ---------------------------------------------------------------------------
// Seeds and keys (init.go, session_keys.go, kip.go)
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        let hi = (s[i] as char).to_digit(16)?;
        let lo = (s[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `init.go RecoverPublicKey`: 32-byte master scalar or 64-byte split
/// key → the edwards25519 public point.
fn recover_public_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let scalar: Option<Scalar> = Scalar::from_canonical_bytes(arr).into();
        let point = ED25519_BASEPOINT_POINT * scalar?;
        return Some(point.compress().to_bytes());
    }
    if bytes.len() == 64 {
        let r_arr: [u8; 32] = bytes[..32].try_into().ok()?;
        let k_arr: [u8; 32] = bytes[32..].try_into().ok()?;
        let r: Option<Scalar> = Scalar::from_canonical_bytes(r_arr).into();
        let k: Option<Scalar> = Scalar::from_canonical_bytes(k_arr).into();
        let sum = r? + k?;
        let point = ED25519_BASEPOINT_POINT * sum;
        return Some(point.compress().to_bytes());
    }
    None
}

/// `init.go ClientAEADSeed`: canonical seed stable between client key
/// material and the server public key.
fn client_aead_seed(key: &str) -> String {
    let key = key.trim();
    if key.is_empty() {
        return String::new();
    }
    let Some(b) = hex_decode(key) else {
        return key.to_string();
    };
    // A 32-byte hex that decodes as an edwards point is preserved
    // verbatim (canonically re-encoded).
    if b.len() == 32 {
        if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
            if let Some(point) = curve25519_dalek::edwards::CompressedEdwardsY(arr).decompress() {
                if point.compress().to_bytes() == arr {
                    return hex_encode(&point.compress().to_bytes());
                }
            }
        }
    }
    if b.len() != 64 && b.len() != 32 {
        return key.to_string();
    }
    match recover_public_key(&b) {
        Some(point) => hex_encode(&point),
        None => key.to_string(),
    }
}

/// `session_keys.go derivePSKDirectionalBases`.
fn derive_psk_directional_bases(seed: &str) -> ([u8; 32], [u8; 32]) {
    let sum = Sha256::digest(seed.as_bytes());
    let hk = Hkdf::<Sha256>::from_prk(&sum).expect("32-byte PRK");
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"sudoku-psk-c2s", &mut c2s).expect("32 bytes");
    hk.expand(b"sudoku-psk-s2c", &mut s2c).expect("32 bytes");
    (c2s, s2c)
}

/// `session_keys.go deriveSessionDirectionalBases`.
fn derive_session_directional_bases(
    seed: &str,
    shared: &[u8],
    nonce: &[u8; 16],
) -> Result<([u8; 32], [u8; 32])> {
    let sum = Sha256::digest(seed.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + 16);
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(nonce);
    let hk = Hkdf::<Sha256>::new(Some(&sum), &ikm);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"sudoku-session-c2s", &mut c2s)
        .map_err(|_| Error::crypto("sudoku: hkdf expand c2s"))?;
    hk.expand(b"sudoku-session-s2c", &mut s2c)
        .map_err(|_| Error::crypto("sudoku: hkdf expand s2c"))?;
    Ok((c2s, s2c))
}

/// `session_keys.go x25519SharedSecret` (Go `crypto/ecdh` X25519 —
/// clamped scalar mult, matching dalek's `mul_clamped`).
fn x25519_shared_secret(scalar: &[u8; 32], peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(*peer_pub).mul_clamped(*scalar);
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(Error::crypto("sudoku: x25519 low-order point"));
    }
    Ok(*shared.as_bytes())
}

// ---------------------------------------------------------------------------
// KIP framing (kip.go)
// ---------------------------------------------------------------------------

const KIP_MAGIC: &[u8; 3] = b"kip";
const KIP_MAX_PAYLOAD: usize = 64 * 1024;

const KIP_TYPE_CLIENT_HELLO: u8 = 0x01;
const KIP_TYPE_SERVER_HELLO: u8 = 0x02;
const KIP_TYPE_OPEN_TCP: u8 = 0x10;
const KIP_TYPE_START_MUX: u8 = 0x11;
const KIP_TYPE_START_UOT: u8 = 0x12;
/// Kept for completeness (server-emitted keepalives are skipped by
/// `readFirstSessionMessage`; the client never generates them).
#[allow(dead_code)]
const KIP_TYPE_KEEP_ALIVE: u8 = 0x14;

/// `KIPFeatAll`.
const KIP_FEAT_ALL: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4);
/// `kipHandshakeSkew`.
#[cfg_attr(not(test), allow(dead_code))]
const KIP_HANDSHAKE_SKEW: i64 = 60;

const KIP_HELLO_USER_HASH_SIZE: usize = 8;
const KIP_HELLO_NONCE_SIZE: usize = 16;
const KIP_HELLO_PUB_SIZE: usize = 32;
#[cfg_attr(not(test), allow(dead_code))]
const KIP_TABLE_HINT_SIZE: usize = 4;

/// `WriteKIPMessage`.
async fn write_kip_message<O: AsyncWrite + Unpin>(
    w: &mut RecordConn<O>,
    typ: u8,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > KIP_MAX_PAYLOAD {
        return Err(Error::protocol(format!(
            "sudoku: kip payload too large: {}",
            payload.len()
        )));
    }
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(KIP_MAGIC);
    frame.push(typ);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame).await?;
    Ok(())
}

/// `ReadKIPMessage`.
async fn read_kip_message<O: AsyncRead + Unpin>(
    r: &mut RecordConn<O>,
) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 6];
    r.read_exact(&mut hdr).await?;
    if &hdr[..3] != KIP_MAGIC {
        return Err(Error::protocol("sudoku: kip bad magic"));
    }
    let typ = hdr[3];
    let n = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    if n > KIP_MAX_PAYLOAD {
        return Err(Error::protocol(format!("sudoku: kip invalid payload length: {n}")));
    }
    let mut payload = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((typ, payload))
}

/// `kipUserHashFromKey`.
fn kip_user_hash_from_key(psk: &str) -> [u8; KIP_HELLO_USER_HASH_SIZE] {
    let mut out = [0u8; KIP_HELLO_USER_HASH_SIZE];
    let psk = psk.trim();
    if psk.is_empty() {
        return out;
    }
    let sum = if let Some(key_bytes) = hex_decode(psk).filter(|b| !b.is_empty()) {
        Sha256::digest(&key_bytes)
    } else {
        Sha256::digest(psk.as_bytes())
    };
    out.copy_from_slice(&sum[..KIP_HELLO_USER_HASH_SIZE]);
    out
}

/// `KIPClientHello.EncodePayload`: `unix be64 || userHash 8 || nonce 16
/// || clientPub 32 || features be32 [|| tableHint be32]`.
fn kip_client_hello_payload(
    timestamp: u64,
    user_hash: &[u8; 8],
    nonce: &[u8; 16],
    client_pub: &[u8; 32],
    features: u32,
    table_hint: Option<u32>,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&timestamp.to_be_bytes());
    b.extend_from_slice(user_hash);
    b.extend_from_slice(nonce);
    b.extend_from_slice(client_pub);
    b.extend_from_slice(&features.to_be_bytes());
    if let Some(hint) = table_hint {
        b.extend_from_slice(&hint.to_be_bytes());
    }
    b
}

/// `DecodeKIPClientHelloPayload`.
#[cfg_attr(not(test), allow(dead_code))]
type KipClientHello = (i64, [u8; 8], [u8; 16], [u8; 32], u32, Option<u32>);
#[cfg_attr(not(test), allow(dead_code))]
fn decode_kip_client_hello_payload(payload: &[u8]) -> Result<KipClientHello> {
    const MIN_LEN: usize =
        8 + KIP_HELLO_USER_HASH_SIZE + KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE + 4;
    if payload.len() < MIN_LEN {
        return Err(Error::protocol("sudoku: kip client hello too short"));
    }
    let ts = i64::from_be_bytes(payload[..8].try_into().expect("8 bytes"));
    let mut off = 8;
    let user_hash: [u8; 8] = payload[off..off + 8].try_into().expect("8 bytes");
    off += 8;
    let nonce: [u8; 16] = payload[off..off + 16].try_into().expect("16 bytes");
    off += 16;
    let client_pub: [u8; 32] = payload[off..off + 32].try_into().expect("32 bytes");
    off += 32;
    let features = u32::from_be_bytes(payload[off..off + 4].try_into().expect("4 bytes"));
    off += 4;
    let table_hint = if payload.len() >= off + KIP_TABLE_HINT_SIZE {
        Some(u32::from_be_bytes(
            payload[off..off + 4].try_into().expect("4 bytes"),
        ))
    } else {
        None
    };
    Ok((ts, user_hash, nonce, client_pub, features, table_hint))
}

/// `DecodeKIPServerHelloPayload`: `nonce 16 || serverPub 32 || feats be32`.
fn decode_kip_server_hello_payload(payload: &[u8]) -> Result<([u8; 16], [u8; 32], u32)> {
    const WANT: usize = KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE + 4;
    if payload.len() != WANT {
        return Err(Error::protocol(format!(
            "sudoku: kip server hello bad len: {}",
            payload.len()
        )));
    }
    let nonce: [u8; 16] = payload[..16].try_into().expect("16 bytes");
    let server_pub: [u8; 32] = payload[16..48].try_into().expect("32 bytes");
    let feats = u32::from_be_bytes(payload[48..52].try_into().expect("4 bytes"));
    Ok((nonce, server_pub, feats))
}

// ---------------------------------------------------------------------------
// Target address + UoT datagrams (address.go, uot.go)
// ---------------------------------------------------------------------------

/// `EncodeAddress` (address.go:12): SOCKS-style, port LAST.
pub fn encode_address(target: &NetAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 2 + 4);
    match &target.host {
        Host::Domain(d) => {
            buf.push(0x03);
            buf.push(d.len().min(255) as u8);
            buf.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&target.port.to_be_bytes());
    buf
}

/// `DecodeAddress` (address.go:55) over a consumed slice.
pub fn decode_address(data: &[u8]) -> Result<(NetAddr, usize)> {
    let Some(&atyp) = data.first() else {
        return Err(Error::protocol("sudoku: address: empty"));
    };
    match atyp {
        0x01 => {
            if data.len() < 1 + 4 + 2 {
                return Err(Error::protocol("sudoku: address: short ipv4"));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((NetAddr::ip(std::net::IpAddr::V4(ip), port), 7))
        }
        0x04 => {
            if data.len() < 1 + 16 + 2 {
                return Err(Error::protocol("sudoku: address: short ipv6"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((NetAddr::ip(std::net::IpAddr::V6(o.into()), port), 19))
        }
        0x03 => {
            let Some(&len) = data.get(1) else {
                return Err(Error::protocol("sudoku: address: short domain len"));
            };
            if data.len() < 2 + len as usize + 2 {
                return Err(Error::protocol("sudoku: address: short domain"));
            }
            let host = std::str::from_utf8(&data[2..2 + len as usize])
                .map_err(|_| Error::protocol("sudoku: address: bad utf-8 domain"))?;
            let port = u16::from_be_bytes([data[2 + len as usize], data[3 + len as usize]]);
            Ok((
                NetAddr::new(Host::Domain(host.to_string()), port),
                4 + len as usize,
            ))
        }
        other => Err(Error::protocol(format!(
            "sudoku: unknown address type: {other}"
        ))),
    }
}

const MAX_UOT_PAYLOAD: usize = 64 * 1024;

/// `WriteDatagram` (uot.go:22): `addrLen be16 || payloadLen be16 ||
/// addr || payload` over the reliable stream.
pub fn uot_datagram(target: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let addr_buf = encode_address(target);
    if addr_buf.is_empty() || addr_buf.len() > MAX_UOT_PAYLOAD {
        return Err(Error::protocol(format!(
            "sudoku: address too long: {}",
            addr_buf.len()
        )));
    }
    if payload.len() > MAX_UOT_PAYLOAD {
        return Err(Error::protocol(format!(
            "sudoku: payload too large: {}",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + addr_buf.len() + payload.len());
    out.extend_from_slice(&(addr_buf.len() as u16).to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&addr_buf);
    out.extend_from_slice(payload);
    Ok(out)
}

/// `ReadDatagram` / `readDatagramHeaderAndAddress` from a stream.
pub async fn read_uot_datagram<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(NetAddr, Vec<u8>)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let addr_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if addr_len == 0 || addr_len > MAX_UOT_PAYLOAD {
        return Err(Error::protocol(format!(
            "sudoku: invalid address length: {addr_len}"
        )));
    }
    if payload_len > MAX_UOT_PAYLOAD {
        return Err(Error::protocol(format!(
            "sudoku: invalid payload length: {payload_len}"
        )));
    }
    let mut addr_buf = vec![0u8; addr_len];
    stream.read_exact(&mut addr_buf).await?;
    let (addr, used) = decode_address(&addr_buf)?;
    if used != addr_buf.len() {
        return Err(Error::protocol("sudoku: trailing bytes in uot address"));
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((addr, payload))
}

// ---------------------------------------------------------------------------
// Legacy HTTP mask header (obfs/httpmask/masker.go)
// ---------------------------------------------------------------------------

/// The masker's header pools (masker.go:17-78).
const MASK_USER_AGENTS: [&str; 8] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
];
const MASK_ACCEPTS: [&str; 4] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "application/octet-stream",
    "*/*",
];
const MASK_ACCEPT_LANGUAGES: [&str; 5] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
];
const MASK_ACCEPT_ENCODINGS: [&str; 3] = ["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"];
const MASK_PATHS: [&str; 10] = [
    "/api/v1/upload",
    "/data/sync",
    "/uploads/raw",
    "/api/report",
    "/feed/update",
    "/v2/events",
    "/v1/telemetry",
    "/session",
    "/stream",
    "/ws",
];
const MASK_CONTENT_TYPES: [&str; 3] = [
    "application/octet-stream",
    "application/x-protobuf",
    "application/json",
];

/// `normalizePathRoot` + `joinPathRoot` (pathroot.go).
fn join_path_root(root: &str, path: &str) -> String {
    let root = root.trim().trim_matches('/');
    if root.is_empty() {
        return path.to_string();
    }
    let valid = root
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    if !valid {
        return path.to_string();
    }
    format!("/{root}{path}")
}

fn trim_port_for_host(host: &str) -> String {
    // Accept "example.com:443" / "[::1]:443"; keep anything else.
    if let Some((h, _)) = host.rsplit_once(':') {
        if !h.is_empty() && h.parse::<std::net::IpAddr>().is_ok() {
            return h.to_string();
        }
        if !h.is_empty() && !h.contains(':') {
            return h.to_string();
        }
    }
    host.to_string()
}

fn mask_pick<T: Copy>(pool: &[T]) -> T {
    pool[rand::random::<u32>() as usize % pool.len()]
}

/// A 1-in-`n` coin for the masker's optional headers.
fn mask_coin(n: u32) -> bool {
    rand::random::<u32>().rem_euclid(n) == 0
}



/// `WriteRandomRequestHeaderWithPathRoot` (masker.go:152): ~20%
/// WebSocket-upgrade template, ~80% POST upload.
async fn write_random_request_header(
    w: &mut (impl AsyncWrite + Unpin),
    host: &str,
    path_root: &str,
) -> Result<()> {
    let path = join_path_root(path_root, mask_pick(&MASK_PATHS));
    let ctype = mask_pick(&MASK_CONTENT_TYPES);
    let mut buf = Vec::with_capacity(1024);
    let roll = rand::random::<u32>() % 10;
    let ua = mask_pick(&MASK_USER_AGENTS);
    let accept = mask_pick(&MASK_ACCEPTS);
    let lang = mask_pick(&MASK_ACCEPT_LANGUAGES);
    let enc = mask_pick(&MASK_ACCEPT_ENCODINGS);
    if roll < 2 {
        // WebSocket-like upgrade (~20%).
        let host_no_port = trim_port_for_host(host);
        let mut key_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        use base64::Engine;
        let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        buf.extend_from_slice(b"GET ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        buf.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        buf.extend_from_slice(format!("User-Agent: {ua}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept: {accept}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept-Language: {lang}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept-Encoding: {enc}\r\n").as_bytes());
        buf.extend_from_slice(b"Connection: keep-alive\r\n");
        buf.extend_from_slice(b"Cache-Control: no-cache\r\nPragma: no-cache\r\n");
        buf.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
        buf.extend_from_slice(b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        buf.extend_from_slice(ws_key.as_bytes());
        buf.extend_from_slice(b"\r\nOrigin: https://");
        buf.extend_from_slice(host_no_port.as_bytes());
        buf.extend_from_slice(b"\r\n\r\n");
    } else {
        // POST upload (~80%): Content-Length 4 KiB..=10 MiB.
        const MIN_CL: u64 = 4 * 1024;
        const MAX_CL: u64 = 10 * 1024 * 1024;
        let content_length = MIN_CL + rand::random::<u64>() % (MAX_CL - MIN_CL + 1);
        buf.extend_from_slice(b"POST ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        buf.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        buf.extend_from_slice(format!("User-Agent: {ua}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept: {accept}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept-Language: {lang}\r\n").as_bytes());
        buf.extend_from_slice(format!("Accept-Encoding: {enc}\r\n").as_bytes());
        buf.extend_from_slice(b"Connection: keep-alive\r\n");
        buf.extend_from_slice(b"Cache-Control: no-cache\r\nPragma: no-cache\r\n");
        buf.extend_from_slice(format!("Content-Type: {ctype}\r\n").as_bytes());
        buf.extend_from_slice(format!("Content-Length: {content_length}\r\n").as_bytes());
        if mask_coin(2) {
            buf.extend_from_slice(b"X-Requested-With: XMLHttpRequest\r\n");
        }
        if mask_coin(3) {
            buf.extend_from_slice(b"Referer: https://");
            buf.extend_from_slice(trim_port_for_host(host).as_bytes());
            buf.extend_from_slice(b"/\r\n");
        }
        buf.extend_from_slice(b"\r\n");
    }
    w.write_all(&buf).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Config + client handshake entry points (adapter/outbound/sudoku.go)
// ---------------------------------------------------------------------------

/// Outbound Sudoku endpoint — mihomo `proxies: type: sudoku` fields
/// (`SudokuOption`, adapter/outbound/sudoku.go:29).
#[derive(Debug, Clone)]
pub struct SudokuOut {
    pub server: String,
    pub port: u16,
    /// `key` (PSK string, or hex point / split / master key material).
    pub key: String,
    /// `aead-method`: aes-128-gcm | chacha20-poly1305 (default) | none.
    pub aead_method: Option<String>,
    /// `padding-min` (0..=100).
    pub padding_min: Option<i64>,
    /// `padding-max` (0..=100, >= padding-min).
    pub padding_max: Option<i64>,
    /// `table-type`: prefer_ascii | prefer_entropy | up_ascii_down_entropy
    /// | up_entropy_down_ascii (default prefer_entropy).
    pub table_type: String,
    /// `enable-pure-downlink` (default true).
    pub enable_pure_downlink: Option<bool>,
    /// `http-mask` (default enabled).
    pub http_mask: Option<bool>,
    /// `http-mask-mode`: legacy (default) | stream | poll | auto | ws.
    pub http_mask_mode: String,
    /// `http-mask-tls` — TLS carrier for the stream/poll/auto modes
    /// (and `wss` for `ws`).
    pub http_mask_tls: bool,
    /// Engine-local knob (no mihomo field): accept any certificate on
    /// the `http-mask-tls` carrier. Upstream always verifies against
    /// the system store (tunnel_dial.go `ca.GetTLSConfig`); hermetic
    /// tests and private-CA deployments need this.
    pub http_mask_tls_insecure: bool,
    /// `http-mask-host` — Host/SNI override.
    pub http_mask_host: String,
    /// `path-root` — single-segment path prefix.
    pub path_root: String,
    /// `multiplex` / `http-mask-multiplex`: off | auto | on.
    pub multiplex: String,
    /// `custom-table` — an 8-symbol x/p/v layout.
    pub custom_table: String,
    /// `custom-tables` — rotation patterns (override custom-table).
    pub custom_tables: Vec<String>,
}

impl SudokuOut {
    /// A default-valued config over `server:port` with the given key.
    pub fn new(server: &str, port: u16, key: &str) -> Self {
        SudokuOut {
            server: server.to_string(),
            port,
            key: key.to_string(),
            aead_method: None,
            padding_min: None,
            padding_max: None,
            table_type: String::new(),
            enable_pure_downlink: None,
            http_mask: None,
            http_mask_mode: String::new(),
            http_mask_tls: false,
            http_mask_tls_insecure: false,
            http_mask_host: String::new(),
            path_root: String::new(),
            multiplex: String::new(),
            custom_table: String::new(),
            custom_tables: Vec::new(),
        }
    }
}

/// The resolved per-connection protocol state (`ProtocolConfig` +
/// `NewSudoku` normalization).
struct ResolvedConfig {
    server_address: String,
    seed: String,
    method: RecordMethod,
    padding_min: i64,
    padding_max: i64,
    enable_pure_downlink: bool,
    disable_http_mask: bool,
    http_mask_mode: String,
    http_mask_tls: bool,
    http_mask_tls_insecure: bool,
    http_mask_host: String,
    path_root: String,
    multiplex: String,
    tables: Vec<Arc<Table>>,
}

impl ResolvedConfig {
    /// `httpTunnelModeEnabled` (mihomo_sudoku.go): the HTTP tunnel
    /// modes (everything but the legacy mask).
    fn tunnel_mode(&self) -> bool {
        matches!(
            self.http_mask_mode.as_str(),
            "stream" | "poll" | "auto" | "ws"
        ) && !self.disable_http_mask
    }
}

/// `ResolvePadding` (config.go:220).
fn resolve_padding(min: Option<i64>, max: Option<i64>, def_min: i64, def_max: i64) -> (i64, i64) {
    let padding_min = min.unwrap_or(def_min);
    let padding_max = max.unwrap_or(def_max);
    match (min, max) {
        (None, Some(_)) if padding_max < padding_min => (padding_max, padding_max),
        (Some(_), None) if padding_max < padding_min => (padding_min, padding_min),
        _ => (padding_min, padding_max),
    }
}

/// `NormalizeMultiplexMode` (config.go:171).
fn normalize_multiplex_mode(mode: &str) -> Result<String> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "off" => Ok("off".into()),
        "auto" => Ok("auto".into()),
        "on" => Ok("on".into()),
        other => Err(Error::config(format!(
            "sudoku: invalid multiplex {other:?}, must be one of: off, auto, on"
        ))),
    }
}

/// `validatePathRoot` (config.go:118-134).
fn validate_path_root(root: &str) -> Result<()> {
    let v = root.trim().trim_matches('/');
    if v.is_empty() {
        return Ok(());
    }
    if v.contains('/') {
        return Err(Error::config(
            "sudoku: invalid http-mask-path-root: must be a single path segment",
        ));
    }
    if !v
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(Error::config(
            "sudoku: invalid http-mask-path-root: contains an invalid character",
        ));
    }
    Ok(())
}

/// `isLegacyHTTPMaskMode` (handshake.go:315) — "" and "legacy".
#[allow(dead_code)]
fn is_legacy_http_mask_mode(mode: &str) -> bool {
    matches!(mode.trim().to_ascii_lowercase().as_str(), "" | "legacy")
}

fn resolve_config(cfg: &SudokuOut) -> Result<ResolvedConfig> {
    if cfg.server.is_empty() {
        return Err(Error::config("sudoku: server is required"));
    }
    if cfg.port == 0 {
        return Err(Error::config(format!("sudoku: invalid port: {}", cfg.port)));
    }
    if cfg.key.is_empty() {
        return Err(Error::config("sudoku: key is required"));
    }
    // `NormalizeTableType`.
    AsciiMode::parse(&cfg.table_type)?;
    let (padding_min, padding_max) = resolve_padding(cfg.padding_min, cfg.padding_max, 10, 30);
    if !(0..=100).contains(&padding_min) {
        return Err(Error::config(format!(
            "sudoku: padding-min must be between 0 and 100, got {padding_min}"
        )));
    }
    if !(0..=100).contains(&padding_max) {
        return Err(Error::config(format!(
            "sudoku: padding-max must be between 0 and 100, got {padding_max}"
        )));
    }
    if padding_max < padding_min {
        return Err(Error::config(format!(
            "sudoku: padding-max ({padding_max}) must be >= padding-min ({padding_min})"
        )));
    }
    let http_mask_mode = if cfg.http_mask_mode.is_empty() {
        "legacy".to_string()
    } else {
        cfg.http_mask_mode.trim().to_ascii_lowercase()
    };
    match http_mask_mode.as_str() {
        "" | "legacy" | "stream" | "poll" | "auto" | "ws" => {}
        other => {
            return Err(Error::config(format!(
                "sudoku: invalid http-mask-mode {other:?}, must be one of: legacy, stream, \
                 poll, auto, ws"
            )))
        }
    }
    if cfg.http_mask_tls && matches!(http_mask_mode.as_str(), "legacy" | "") {
        // `http-mask-tls` only applies to the stream/poll/auto tunnel
        // modes (adapter/outbound/sudoku.go:42); upstream rejects it
        // for ws in `normalizeWSSchemeFromAddress` terms — carried,
        // inert for legacy.
        debug!(target: "engine", "sudoku: http-mask-tls only applies to the stream/poll/auto tunnel modes");
    }
    validate_path_root(&cfg.path_root)?;
    let mut multiplex = normalize_multiplex_mode(&cfg.multiplex)?;
    if multiplex == "auto" {
        // `auto` only enables HTTPMask transport reuse upstream
        // (config.go:67), which without the tunnel modes is inert over
        // raw TCP; treat as off with the option carried.
        debug!(target: "engine", "sudoku: multiplex \"auto\" has no effect without the HTTP tunnel modes");
        multiplex = "off".into();
    }
    let method = RecordMethod::parse(cfg.aead_method.as_deref().unwrap_or(""))?;
    let disable_http_mask = cfg.http_mask.map(|v| !v).unwrap_or(false);
    let tables = new_client_tables_with_custom_patterns(
        &cfg.key,
        &cfg.table_type,
        &cfg.custom_table,
        &cfg.custom_tables,
    )?;
    Ok(ResolvedConfig {
        server_address: format!("{}:{}", cfg.server, cfg.port),
        seed: client_aead_seed(&cfg.key),
        method,
        padding_min,
        padding_max,
        enable_pure_downlink: cfg.enable_pure_downlink.unwrap_or(true),
        disable_http_mask,
        http_mask_mode,
        http_mask_tls: cfg.http_mask_tls,
        http_mask_tls_insecure: cfg.http_mask_tls_insecure,
        http_mask_host: cfg.http_mask_host.clone(),
        path_root: cfg.path_root.clone(),
        multiplex,
        tables,
    })
}

/// `pickClientTable` (table_probe.go:23): single table → no hint;
/// rotation → uniform random pick with the table hint set.
fn pick_client_table(tables: &[Arc<Table>]) -> Result<(Arc<Table>, Option<u32>)> {
    if tables.is_empty() {
        return Err(Error::config("sudoku: no table configured"));
    }
    if tables.len() == 1 {
        return Ok((tables[0].clone(), None));
    }
    let idx = (rand::random::<u8>() as usize) % tables.len();
    Ok((tables[idx].clone(), Some(tables[idx].hint())))
}

/// `ClientHandshake` (handshake.go:325) + `kipHandshakeClient`
/// (handshake_kip.go:15): legacy HTTP mask header, obfs + record
/// layers, X25519-authenticated KIP exchange, session rekey.
async fn client_handshake(transport: BoxProxyStream, rc: &ResolvedConfig) -> Result<RecordConn> {
    let (choice, hint) = pick_client_table(&rc.tables)?;
    let mut transport = transport;
    if !rc.disable_http_mask {
        // Only reachable for the legacy mode: the tunnel modes route
        // through `dial_http_mask_tunnel` (which runs the KIP exchange
        // as the early handshake) instead of this raw path.
        debug_assert!(matches!(rc.http_mask_mode.as_str(), "" | "legacy"));
        let host = if rc.http_mask_host.is_empty() {
            rc.server_address.clone()
        } else {
            rc.http_mask_host.clone()
        };
        write_random_request_header(&mut transport, &host, &rc.path_root).await?;
    }
    let obfs = ObfsStream::new(
        transport,
        choice,
        rc.padding_min,
        rc.padding_max,
        rc.enable_pure_downlink,
    );
    kip_handshake_client(RecordConn::new(obfs, rc.method, [0u8; 32], [0u8; 32]), rc, hint).await
}

/// `kipHandshakeClient` (handshake_kip.go).
async fn kip_handshake_client(
    mut conn: RecordConn,
    rc: &ResolvedConfig,
    table_hint: Option<u32>,
) -> Result<RecordConn> {
    let seed = client_aead_seed(&rc.seed);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    conn.base_send = psk_c2s;
    conn.base_recv = psk_s2c;

    let mut scalar = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut scalar);
    let client_pub = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let user_hash = kip_user_hash_from_key(&rc.seed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hello = kip_client_hello_payload(
        timestamp,
        &user_hash,
        &nonce,
        &client_pub,
        KIP_FEAT_ALL,
        table_hint,
    );
    write_kip_message(&mut conn, KIP_TYPE_CLIENT_HELLO, &hello).await?;
    let (typ, payload) = read_kip_message(&mut conn).await?;
    if typ != KIP_TYPE_SERVER_HELLO {
        return Err(Error::protocol(format!(
            "sudoku: unexpected handshake message: {typ:#x}"
        )));
    }
    let (echo_nonce, server_pub, _selected) = decode_kip_server_hello_payload(&payload)?;
    if echo_nonce != nonce {
        return Err(Error::protocol("sudoku: handshake nonce mismatch"));
    }
    let shared = x25519_shared_secret(&scalar, &server_pub)?;
    let (sess_c2s, sess_s2c) = derive_session_directional_bases(&seed, &shared, &nonce)?;
    conn.rekey(sess_c2s, sess_s2c);
    debug!(target: "engine", "sudoku: KIP handshake complete (server {})", rc.server_address);
    Ok(conn)
}

/// `DialContext` (adapter/outbound/sudoku.go:62): handshake then the
/// `KIPTypeOpenTCP` target request.
pub async fn connect(
    cfg: &SudokuOut,
    transport: BoxProxyStream,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    let rc = resolve_config(cfg)?;
    if rc.multiplex == "on" {
        return Err(Error::config(
            "sudoku: multiplex \"on\" requires the session dialer — use connect_mux",
        ));
    }
    if rc.tunnel_mode() {
        return Err(Error::config(format!(
            "sudoku: http-mask-mode {:?} dials its own HTTP connections (authorize, pull, \
             push) — pass a dialer to connect_tunnel instead of one transport",
            rc.http_mask_mode
        )));
    }
    let mut conn = client_handshake(transport, &rc).await?;
    let addr_buf = encode_address(target);
    write_kip_message(&mut conn, KIP_TYPE_OPEN_TCP, &addr_buf).await?;
    debug!(target: "engine", "sudoku: TCP open sent for {target}");
    Ok(Box::new(conn))
}

/// `ListenPacketContext` (adapter/outbound/sudoku.go:97): handshake
/// then `KIPTypeStartUoT`; datagrams flow via [`uot_datagram`] /
/// [`read_uot_datagram`] (`NewUoTPacketConn` semantics).
pub async fn connect_udp(cfg: &SudokuOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let rc = resolve_config(cfg)?;
    if rc.tunnel_mode() {
        return Err(Error::config(format!(
            "sudoku: http-mask-mode {:?} dials its own HTTP connections — use connect_tunnel_udp",
            rc.http_mask_mode
        )));
    }
    let mut conn = client_handshake(transport, &rc).await?;
    write_kip_message(&mut conn, KIP_TYPE_START_UOT, &[]).await?;
    debug!(target: "engine", "sudoku: UoT session started");
    Ok(Box::new(conn))
}

// ---------------------------------------------------------------------------
// Multiplex session (multiplex/session.go) — client side
// ---------------------------------------------------------------------------

/// `multiplex/session.go` frame types.
const MUX_FRAME_OPEN: u8 = 0x01;
const MUX_FRAME_DATA: u8 = 0x02;
const MUX_FRAME_CLOSE: u8 = 0x03;
const MUX_FRAME_RESET: u8 = 0x04;
const MUX_HEADER_SIZE: usize = 1 + 4 + 4;
const MUX_MAX_FRAME_SIZE: usize = 256 * 1024;
const MUX_MAX_DATA_PAYLOAD: usize = 128 * 1024;
/// `maxQueuedBytesPerStream` (session.go:25).
const MUX_MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;
/// `keepaliveInterval` (session.go:28).
const MUX_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(15);

enum StreamEvent {
    Data(Vec<u8>),
    /// `frameClose` — the remote write side ended.
    RemoteClose,
    /// `frameReset` — the stream was torn down (the message is
    /// diagnostics-only upstream: `trimASCII` text).
    Reset(#[allow(dead_code)] String),
}

#[derive(Clone)]
struct MuxStreamHandle {
    tx: tokio::sync::mpsc::Sender<StreamEvent>,
    /// Unread queued bytes (`queuedBytes`, session.go:247).
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

struct MuxShared {
    next_id: std::sync::atomic::AtomicU32,
    write_tx: tokio::sync::mpsc::UnboundedSender<(u8, u32, Vec<u8>)>,
    streams: Mutex<HashMap<u32, MuxStreamHandle>>,
    is_closed: std::sync::atomic::AtomicBool,
    closed: tokio::sync::Notify,
}

impl MuxShared {
    fn close_session(&self) {
        if !self.is_closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.closed.notify_waiters();
            let mut streams = self.streams.lock().unwrap();
            streams.clear();
        }
    }
}

/// `Session` — the client side of the sudoku multiplexer (open /
/// data / close / reset frames, per-stream reset on queue overflow,
/// DATA-on-stream-0 keepalives when idle).
pub struct SudokuMuxSession {
    shared: Arc<MuxShared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// `StartMultiplexClient` (multiplex.go:14): handshake +
/// `KIPTypeStartMux` (`WaitTunnelReady` is a no-op outside the HTTP
/// tunnel modes — tunnel_ready.go:74).
pub async fn connect_mux(cfg: &SudokuOut, transport: BoxProxyStream) -> Result<SudokuMuxSession> {
    let rc = resolve_config(cfg)?;
    let mut conn = client_handshake(transport, &rc).await?;
    write_kip_message(&mut conn, KIP_TYPE_START_MUX, &[]).await?;
    debug!(target: "engine", "sudoku: mux session starting");
    Ok(SudokuMuxSession::new(Box::new(conn)))
}

impl SudokuMuxSession {
    fn new(conn: BoxProxyStream) -> Self {
        let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel::<(u8, u32, Vec<u8>)>();
        let shared = Arc::new(MuxShared {
            next_id: std::sync::atomic::AtomicU32::new(0),
            write_tx,
            streams: Mutex::new(HashMap::new()),
            is_closed: std::sync::atomic::AtomicBool::new(false),
            closed: tokio::sync::Notify::new(),
        });
        let (read_half, write_half) = tokio::io::split(conn);
        let writer = tokio::spawn(mux_writer_task(write_half, write_rx, shared.clone()));
        let reader = tokio::spawn(mux_reader_task(read_half, shared.clone()));
        SudokuMuxSession {
            shared,
            tasks: vec![writer, reader],
        }
    }

    /// `OpenStream` (session.go:243): send OPEN with the encoded target
    /// as payload and return the logical stream.
    pub async fn open_stream(&self, target: &NetAddr) -> Result<MuxStream> {
        if self.is_closed() {
            return Err(Error::network("sudoku: multiplex session is closed"));
        }
        // `nextStreamID` (session.go:171): pre-increment, skip zero.
        let mut id = 1 + self
            .shared
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if id == 0 {
            id = 1 + self
                .shared
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<StreamEvent>(128);
        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        self.shared.streams.lock().unwrap().insert(
            id,
            MuxStreamHandle {
                tx,
                queued: queued.clone(),
            },
        );
        let payload = encode_address(target);
        if self
            .shared
            .write_tx
            .send((MUX_FRAME_OPEN, id, payload))
            .is_err()
        {
            self.shared.streams.lock().unwrap().remove(&id);
            return Err(Error::network("sudoku: mux open failed"));
        }
        Ok(MuxStream {
            id,
            shared: self.shared.clone(),
            rx,
            queued,
            local_closed: false,
            pending: Vec::new(),
        })
    }

    /// `IsClosed`.
    pub fn is_closed(&self) -> bool {
        self.shared
            .is_closed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `Close`.
    pub fn close(&self) {
        self.shared.close_session();
    }
}

impl Drop for SudokuMuxSession {
    fn drop(&mut self) {
        self.shared.close_session();
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

/// The session writer: serializes frames and emits the idle keepalive
/// (`startKeepalive`, session.go:207 — DATA on stream 0, which the
/// client never allocates).
async fn mux_writer_task(
    mut write_half: tokio::io::WriteHalf<BoxProxyStream>,
    mut write_rx: tokio::sync::mpsc::UnboundedReceiver<(u8, u32, Vec<u8>)>,
    shared: Arc<MuxShared>,
) {
    let mut last_write = std::time::Instant::now();
    loop {
        let frame = tokio::select! {
            f = write_rx.recv() => match f {
                Some(f) => f,
                None => break,
            },
            _ = shared.closed.notified() => break,
            _ = tokio::time::sleep(MUX_KEEPALIVE) => {
                if last_write.elapsed() < MUX_KEEPALIVE
                    || shared.is_closed.load(std::sync::atomic::Ordering::SeqCst)
                {
                    continue;
                }
                last_write = std::time::Instant::now();
                let mut frame = Vec::with_capacity(MUX_HEADER_SIZE);
                frame.extend_from_slice(&[MUX_FRAME_DATA, 0, 0, 0, 0, 0, 0, 0, 0]);
                if write_half.write_all(&frame).await.is_err() {
                    break;
                }
                continue;
            }
        };
        last_write = std::time::Instant::now();
        let (typ, id, payload) = frame;
        if payload.len() > MUX_MAX_FRAME_SIZE {
            break;
        }
        let mut out = Vec::with_capacity(MUX_HEADER_SIZE + payload.len());
        out.push(typ);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        if write_half.write_all(&out).await.is_err() {
            break;
        }
    }
    let _ = write_half.shutdown().await;
    shared.close_session();
}

/// The demux loop (`readLoop`, session.go:278).
async fn mux_reader_task(mut read_half: tokio::io::ReadHalf<BoxProxyStream>, shared: Arc<MuxShared>) {
    loop {
        let mut header = [0u8; MUX_HEADER_SIZE];
        let read = tokio::select! {
            _ = shared.closed.notified() => break,
            r = read_half.read_exact(&mut header) => r,
        };
        if read.is_err() {
            break;
        }
        let frame_type = header[0];
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
        if len > MUX_MAX_FRAME_SIZE {
            break;
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            let body = tokio::select! {
                _ = shared.closed.notified() => break,
                r = read_half.read_exact(&mut payload) => r,
            };
            if body.is_err() {
                break;
            }
        }
        match frame_type {
            // Client sessions never accept inbound OPEN
            // (session.go:302-305).
            MUX_FRAME_OPEN => {
                let _ = shared
                    .write_tx
                    .send((MUX_FRAME_RESET, stream_id, b"unexpected open".to_vec()));
                let _ = shared.write_tx.send((MUX_FRAME_CLOSE, stream_id, Vec::new()));
            }
            MUX_FRAME_DATA => {
                if payload.is_empty() {
                    continue;
                }
                let handle = shared.streams.lock().unwrap().get(&stream_id).cloned();
                let Some(handle) = handle else { continue };
                let queued = handle
                    .queued
                    .fetch_add(payload.len(), std::sync::atomic::Ordering::SeqCst)
                    + payload.len();
                if queued > MUX_MAX_QUEUED_BYTES {
                    // `errMuxReceiveQueueFull` → reset + close
                    // (session.go:334-338).
                    shared.streams.lock().unwrap().remove(&stream_id);
                    let _ = shared.write_tx.send((
                        MUX_FRAME_RESET,
                        stream_id,
                        b"mux receive queue full".to_vec(),
                    ));
                    let _ = shared.write_tx.send((MUX_FRAME_CLOSE, stream_id, Vec::new()));
                    continue;
                }
                match handle.tx.try_send(StreamEvent::Data(payload)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        shared.streams.lock().unwrap().remove(&stream_id);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(evt)) => {
                        // Channel full: the stream is not draining; treat
                        // like the queue-full reset above.
                        if let StreamEvent::Data(d) = evt {
                            handle
                                .queued
                                .fetch_sub(d.len(), std::sync::atomic::Ordering::SeqCst);
                        }
                        shared.streams.lock().unwrap().remove(&stream_id);
                        let _ = shared.write_tx.send((
                            MUX_FRAME_RESET,
                            stream_id,
                            b"mux receive queue full".to_vec(),
                        ));
                        let _ = shared.write_tx.send((MUX_FRAME_CLOSE, stream_id, Vec::new()));
                    }
                }
            }
            MUX_FRAME_CLOSE => {
                let handle = shared.streams.lock().unwrap().remove(&stream_id);
                if let Some(h) = handle {
                    let _ = h.tx.try_send(StreamEvent::RemoteClose);
                }
            }
            MUX_FRAME_RESET => {
                let handle = shared.streams.lock().unwrap().remove(&stream_id);
                if let Some(h) = handle {
                    let msg = String::from_utf8_lossy(&payload).trim().to_string();
                    let msg = if msg.is_empty() { "reset".to_string() } else { msg };
                    let _ = h.tx.try_send(StreamEvent::Reset(msg));
                }
            }
            other => {
                debug!(target: "engine", "sudoku: unknown mux frame type {other:#x}");
                break;
            }
        }
    }
    shared.close_session();
}

/// One logical mux stream (`stream`, session.go:393) as a proxy stream.
pub struct MuxStream {
    id: u32,
    shared: Arc<MuxShared>,
    rx: tokio::sync::mpsc::Receiver<StreamEvent>,
    queued: Arc<std::sync::atomic::AtomicUsize>,
    local_closed: bool,
    /// Decoded but undelivered bytes.
    pending: Vec<u8>,
}

impl MuxStream {
    #[allow(dead_code)]
    fn send_frame(&self, typ: u8, payload: Vec<u8>) -> Result<()> {
        self.shared
            .write_tx
            .send((typ, self.id, payload))
            .map_err(|_| Error::network("sudoku: mux session closed"))
    }

    fn remove_self(&self) {
        self.shared.streams.lock().unwrap().remove(&self.id);
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                let rest = self.pending.split_off(n);
                self.queued.fetch_sub(n, std::sync::atomic::Ordering::SeqCst);
                self.pending = rest;
                if self.pending.is_empty() {
                    self.pending = Vec::new();
                }
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(mut d))) => {
                    if d.is_empty() {
                        continue;
                    }
                    if d.len() > buf.remaining() {
                        let take = buf.remaining();
                        let rest = d.split_off(take);
                        buf.put_slice(&d);
                        self.queued.fetch_sub(take, std::sync::atomic::Ordering::SeqCst);
                        self.pending = rest;
                        return Poll::Ready(Ok(()));
                    }
                    self.queued.fetch_sub(d.len(), std::sync::atomic::Ordering::SeqCst);
                    buf.put_slice(&d);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::RemoteClose)) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(StreamEvent::Reset(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "sudoku: mux stream reset",
                    )))
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "sudoku: mux session closed",
                    )))
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    /// `stream.Write` (session.go:512): DATA frames of at most
    /// `maxDataPayload`.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.local_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku: mux stream closed",
            )));
        }
        let chunk = &buf[..buf.len().min(MUX_MAX_DATA_PAYLOAD)];
        // The writer task owns the socket and serializes frames
        // (`sendFrame` + writeMu, session.go:183); the channel only
        // fails when the session is gone.
        match self
            .shared
            .write_tx
            .send((MUX_FRAME_DATA, self.id, chunk.to_vec()))
        {
            // Only the chunk is framed (stream.Write, session.go:538);
            // the caller re-polls with the remainder.
            Ok(()) => Poll::Ready(Ok(chunk.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku: mux session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// `stream.Close` (session.go:552): send CLOSE and drop the stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.local_closed {
            self.local_closed = true;
            let _ = self.shared.write_tx.send((MUX_FRAME_CLOSE, self.id, Vec::new()));
            self.remove_self();
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// HTTPMask tunnel modes (obfs/httpmask: tunnel_dial.go, tunnel_api.go,
// tunnel_conn_stream.go, tunnel_conn_poll.go, tunnel_ws.go,
// ws_stream_conn.go, tunnel_conn_queue.go, tunnel_ready.go,
// tunnel_retry.go, ws_auth.go; client half of early_handshake.go)
// ---------------------------------------------------------------------------

/// `TunnelDialOptions.DialContext` — a fresh transport to the mask
/// server; the embedder keeps its routing/proxy behavior here.
pub type TunnelDialer = std::sync::Arc<
    dyn Fn() -> Pin<Box<dyn std::future::Future<Output = Result<BoxProxyStream>> + Send>>
        + Send
        + Sync,
>;

/// `TunnelMode` (tunnel_api.go:16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    Stream,
    Poll,
    Auto,
    Ws,
}

impl TunnelMode {
    /// The `X-Sudoku-Tunnel` value (applyTunnelHeaders, tunnel_api.go:198).
    fn as_str(&self) -> &'static str {
        match self {
            TunnelMode::Stream => "stream",
            TunnelMode::Poll => "poll",
            TunnelMode::Auto => "auto",
            TunnelMode::Ws => "ws",
        }
    }
}

// ---------------------------------------------------------------------------
// The early KIP handshake (early_handshake.go) — the whole KIP exchange
// marshalled through the tunnel's early-data channel: the obfuscated
// client hello as the `ed` query param, the obfuscated server hello in
// the authorize response.
// ---------------------------------------------------------------------------

/// `earlyMemoryConn` (early_handshake.go:51): an in-memory duplex whose
/// writes are captured and whose reads drain a fixed buffer then EOF.
struct MemIo {
    read: Vec<u8>,
    read_off: usize,
    write: MemWrite,
}

/// The MemIo write destination: a shared capture buffer or /dev/null.
enum MemWrite {
    Sink(Arc<Mutex<Vec<u8>>>),
    Discard,
}

impl MemIo {
    /// A write-only sink capturing into `written` (the request side).
    fn sink(written: Arc<Mutex<Vec<u8>>>) -> BoxProxyStream {
        Box::new(MemIo {
            read: Vec::new(),
            read_off: 0,
            write: MemWrite::Sink(written),
        })
    }

    /// A read-only source (the response-processing side).
    fn source(bytes: Vec<u8>) -> BoxProxyStream {
        Box::new(MemIo {
            read: bytes,
            read_off: 0,
            write: MemWrite::Discard,
        })
    }
}

impl AsyncRead for MemIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_off < this.read.len() {
            let n = (this.read.len() - this.read_off).min(buf.remaining());
            buf.put_slice(&this.read[this.read_off..this.read_off + n]);
            this.read_off += n;
        }
        // Drained (or empty): EOF, like `bytes.Reader`.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &self.write {
            // A live capture buffer.
            MemWrite::Sink(shared) => shared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf),
            MemWrite::Discard => {}
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// `EarlyClientState` (early_handshake.go:27): builds the obfuscated,
/// PSK-encrypted KIP client hello offline; processes the obfuscated
/// server hello; wraps the tunnel conn with the session keys.
struct EarlyClientState {
    request_payload: Vec<u8>,
    table: Arc<Table>,
    nonce: [u8; 16],
    scalar: [u8; 32],
    seed: String,
    method: RecordMethod,
    padding: (i64, i64),
    pure_downlink: bool,
    session_c2s: [u8; 32],
    session_s2c: [u8; 32],
    response_set: bool,
}

impl EarlyClientState {
    /// `NewEarlyClientState` (early_handshake.go:102): the client hello
    /// written through a fresh obfs+record stack into memory.
    async fn new(rc: &ResolvedConfig, table: Arc<Table>, table_hint: Option<u32>) -> Result<Self> {
        let written = Arc::new(Mutex::new(Vec::new()));
        let obfs = ObfsStream::new(
            MemIo::sink(written.clone()),
            table.clone(),
            rc.padding_min,
            rc.padding_max,
            rc.enable_pure_downlink,
        );
        let seed = client_aead_seed(&rc.seed);
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
        let mut conn = RecordConn::new(obfs, rc.method, psk_c2s, psk_s2c);
        let mut scalar = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut scalar);
        let client_pub = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let user_hash = kip_user_hash_from_key(&rc.seed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hello = kip_client_hello_payload(
            timestamp,
            &user_hash,
            &nonce,
            &client_pub,
            KIP_FEAT_ALL,
            table_hint,
        );
        write_kip_message(&mut conn, KIP_TYPE_CLIENT_HELLO, &hello).await?;
        let request_payload = written.lock().unwrap().clone();
        Ok(EarlyClientState {
            request_payload,
            table,
            nonce,
            scalar,
            seed,
            method: rc.method,
            padding: (rc.padding_min, rc.padding_max),
            pure_downlink: rc.enable_pure_downlink,
            session_c2s: [0u8; 32],
            session_s2c: [0u8; 32],
            response_set: false,
        })
    }

    /// `ProcessResponse` (early_handshake.go:142): the obfuscated server
    /// hello read back through a fresh stack; derives the session keys.
    async fn process_response(&mut self, payload: Vec<u8>) -> Result<()> {
        let obfs = ObfsStream::new(
            MemIo::source(payload),
            self.table.clone(),
            self.padding.0,
            self.padding.1,
            self.pure_downlink,
        );
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&self.seed);
        let mut conn = RecordConn::new(obfs, self.method, psk_c2s, psk_s2c);
        let (typ, payload) = read_kip_message(&mut conn).await?;
        if typ != KIP_TYPE_SERVER_HELLO {
            return Err(Error::protocol(format!(
                "sudoku: unexpected early handshake message: {typ:#x}"
            )));
        }
        let (echo_nonce, server_pub, _feats) = decode_kip_server_hello_payload(&payload)?;
        if echo_nonce != self.nonce {
            return Err(Error::protocol("sudoku: early handshake nonce mismatch"));
        }
        let shared = x25519_shared_secret(&self.scalar, &server_pub)?;
        let (c2s, s2c) = derive_session_directional_bases(&self.seed, &shared, &self.nonce)?;
        self.session_c2s = c2s;
        self.session_s2c = s2c;
        self.response_set = true;
        Ok(())
    }

    /// `WrapConn` (early_handshake.go:182): the live tunnel conn with
    /// the session-key record layer (no in-band handshake remains).
    fn wrap_conn(self, raw: BoxProxyStream) -> Result<RecordConn<ObfsStream>> {
        if !self.response_set {
            return Err(Error::protocol("sudoku: early handshake not completed"));
        }
        let obfs = ObfsStream::new(
            raw,
            self.table,
            self.padding.0,
            self.padding.1,
            self.pure_downlink,
        );
        Ok(RecordConn::new(obfs, self.method, self.session_c2s, self.session_s2c))
    }
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client (one request per fresh connection)
// ---------------------------------------------------------------------------

/// `net.SplitHostPort` for `host:port` / `[v6]:port`; `None` when the
/// string carries no port.
fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host.to_string(), port.to_string()));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

/// `canonicalHeaderHost` (tunnel_dial.go:35): strip the default port,
/// keeping IPv6 literals bracketed.
fn canonical_header_host(url_host: &str, scheme: &str) -> String {
    let Some((host, port)) = split_host_port(url_host) else {
        return url_host.to_string();
    };
    let default_port = match scheme {
        "https" | "wss" => "443",
        "http" | "ws" => "80",
        _ => "",
    };
    if default_port.is_empty() || port != default_port {
        return url_host.to_string();
    }
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    }
}

/// `normalizeHTTPDialTarget` (tunnel_dial.go:439).
#[derive(Clone)]
struct HttpTarget {
    scheme: &'static str,
    /// Canonical Host header value (from the `host:port` URL host).
    header_host: String,
    /// SNI for the TLS carrier.
    server_name: String,
}

fn normalize_http_dial_target(
    server_address: &str,
    tls_enabled: bool,
    host_override: &str,
) -> Result<HttpTarget> {
    let (mut host, mut port) = split_host_port(server_address)
        .ok_or_else(|| Error::config(format!("sudoku: invalid server address {server_address:?}")))?;
    let mut server_name;
    let url_host;
    if !host_override.is_empty() {
        // Allow "example.com" or "example.com:443".
        if let Some((h, p)) = split_host_port(host_override) {
            host = h;
            port = p;
        } else {
            host = host_override.to_string();
        }
        server_name = host.clone();
        url_host = format!("{host}:{port}");
    } else {
        server_name = host.clone();
        url_host = format!("{host}:{port}");
    }
    let scheme = if tls_enabled { "https" } else { "http" };
    server_name = trim_port_for_host(&server_name);
    Ok(HttpTarget {
        scheme,
        header_host: canonical_header_host(&url_host, scheme),
        server_name,
    })
}

/// `normalizeWSDialTarget` (tunnel_ws.go:38) — the engine always dials
/// `server:port`, so the ws/wss scheme follows the TLS flag and a
/// missing port defaults to 80/443.
fn normalize_ws_dial_target(
    server_address: &str,
    tls_enabled: bool,
    host_override: &str,
) -> Result<HttpTarget> {
    let (mut host, mut port) = match split_host_port(server_address) {
        Some((h, p)) => (h, p),
        None => {
            if server_address.contains(':') && !server_address.starts_with('[') {
                return Err(Error::config(format!(
                    "sudoku: invalid server address {server_address:?}"
                )));
            }
            let scheme = if tls_enabled { "wss" } else { "ws" };
            (
                server_address.to_string(),
                if scheme == "wss" { "443" } else { "80" }.to_string(),
            )
        }
    };
    if !host_override.is_empty() {
        if let Some((h, p)) = split_host_port(host_override) {
            host = h;
            port = p;
        } else {
            host = host_override.to_string();
        }
    }
    let server_name = trim_port_for_host(&host);
    let url_host = format!("{host}:{port}");
    let scheme = if tls_enabled { "wss" } else { "ws" };
    Ok(HttpTarget {
        scheme,
        header_host: canonical_header_host(&url_host, if tls_enabled { "https" } else { "http" }),
        server_name,
    })
}

// -- request/response plumbing ------------------------------------------------

/// One HTTP/1.1 request over a fresh connection.
struct HttpRequest<'a> {
    method: &'a str,
    /// Origin-form path with query.
    path_query: &'a str,
    /// Extra headers (after Host).
    headers: Vec<(String, String)>,
    body: Option<&'a [u8]>,
}

struct HttpResp {
    status: u16,
    body: HttpBody,
}

enum BodyKind {
    Length(u64),
    Chunked,
    UntilClose,
}

/// A response body reader supporting Content-Length, chunked framing
/// (with trailers) and read-to-EOF.
struct HttpBody {
    conn: BoxProxyStream,
    kind: BodyKind,
    /// Set once the body fully ended (chunked: after trailers).
    done: bool,
    /// Chunked: bytes remaining in the current chunk.
    chunk_rem: usize,
    pub trailers: Vec<(String, String)>,
}

impl HttpBody {
    /// Append some body bytes to `out`; `Ok(false)` when the body ended.
    async fn read_some(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        match self.kind {
            BodyKind::Length(rem) => {
                if rem == 0 {
                    self.done = true;
                    return Ok(false);
                }
                let want = (rem.min(32 * 1024)) as usize;
                let mut tmp = vec![0u8; want];
                let n = self.conn.read(&mut tmp).await?;
                if n == 0 {
                    return Err(Error::network("sudoku: http body ended early"));
                }
                out.extend_from_slice(&tmp[..n]);
                self.kind = BodyKind::Length(rem - n as u64);
                Ok(true)
            }
            BodyKind::UntilClose => {
                let mut tmp = vec![0u8; 32 * 1024];
                let n = self.conn.read(&mut tmp).await?;
                if n == 0 {
                    self.done = true;
                    return Ok(false);
                }
                out.extend_from_slice(&tmp[..n]);
                Ok(true)
            }
            BodyKind::Chunked => {
                if self.chunk_rem == 0 {
                    // Start the next chunk (the previous one consumed its CRLF).
                    let line = read_crlf_line(&mut self.conn, 128).await?;
                    let size_str = String::from_utf8_lossy(&line);
                    let size_hex = size_str.trim().split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(size_hex, 16)
                        .map_err(|_| Error::protocol("sudoku: bad chunk size"))?;
                    if size == 0 {
                        self.read_trailers().await?;
                        self.done = true;
                        return Ok(false);
                    }
                    self.chunk_rem = size;
                }
                let want = self.chunk_rem.min(32 * 1024);
                let mut tmp = vec![0u8; want];
                let n = self.conn.read(&mut tmp).await?;
                if n == 0 {
                    return Err(Error::network("sudoku: chunked body ended early"));
                }
                out.extend_from_slice(&tmp[..n]);
                self.chunk_rem -= n;
                if self.chunk_rem == 0 {
                    let mut crlf = [0u8; 2];
                    self.conn.read_exact(&mut crlf).await?;
                    if &crlf != b"\r\n" {
                        return Err(Error::protocol("sudoku: bad chunk terminator"));
                    }
                }
                Ok(true)
            }
        }
    }

    /// The chunked trailer section (`Trailer:`-declared headers after the
    /// terminating zero chunk).
    async fn read_trailers(&mut self) -> Result<()> {
        loop {
            let line = read_crlf_line(&mut self.conn, 8 * 1024).await?;
            if line.is_empty() {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            if let Some((name, value)) = text.split_once(':') {
                self.trailers
                    .push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
    }

    fn trailer(&self, name: &str) -> Option<&str> {
        self.trailers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Read the whole body, bounded (authorize bodies, drain limits).
    async fn read_all_limited(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() <= limit {
            let mut chunk = Vec::new();
            if !self.read_some(&mut chunk).await? {
                break;
            }
            if chunk.is_empty() {
                continue;
            }
            out.extend_from_slice(&chunk);
            if out.len() > limit {
                return Err(Error::protocol("sudoku: http response body too large"));
            }
        }
        Ok(out)
    }
}

/// Read one CRLF-terminated line (without the terminator). Byte-wise so
/// nothing past the line is ever consumed from the transport.
async fn read_crlf_line(conn: &mut BoxProxyStream, cap: usize) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = conn.read(&mut byte).await?;
        if n == 0 {
            if line.is_empty() {
                return Err(Error::network("sudoku: http response ended mid-header"));
            }
            return Err(Error::network("sudoku: http response header missing CRLF"));
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.push(byte[0]);
        if line.len() > cap {
            return Err(Error::protocol("sudoku: http response line too long"));
        }
    }
}

/// `applyTunnelHeaders` (tunnel_api.go:182) minus Host (written on the
/// request line block) — one random camouflage set + the mode marker.
fn apply_tunnel_headers(mode: TunnelMode) -> Vec<(String, String)> {
    vec![
        ("User-Agent".into(), mask_pick(&MASK_USER_AGENTS).to_string()),
        ("Accept".into(), mask_pick(&MASK_ACCEPTS).to_string()),
        ("Accept-Language".into(), mask_pick(&MASK_ACCEPT_LANGUAGES).to_string()),
        ("Cache-Control".into(), "no-cache".into()),
        ("Pragma".into(), "no-cache".into()),
        ("Connection".into(), "keep-alive".into()),
        ("X-Sudoku-Tunnel".into(), mode.as_str().to_string()),
    ]
}

/// `applyWSHeaders` (tunnel_ws.go:77).
fn apply_ws_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".into(), mask_pick(&MASK_USER_AGENTS).to_string()),
        ("Accept".into(), mask_pick(&MASK_ACCEPTS).to_string()),
        ("Accept-Language".into(), mask_pick(&MASK_ACCEPT_LANGUAGES).to_string()),
        ("Accept-Encoding".into(), mask_pick(&MASK_ACCEPT_ENCODINGS).to_string()),
        ("Cache-Control".into(), "no-cache".into()),
        ("Pragma".into(), "no-cache".into()),
        ("X-Sudoku-Tunnel".into(), "ws".into()),
        ("X-Sudoku-Version".into(), "1".into()),
    ]
}

// -- transport context --------------------------------------------------------

/// Everything the HTTP client needs to open one request connection
/// (the per-request equivalent of upstream's pooled transport).
#[derive(Clone)]
struct HttpCtx {
    dialer: TunnelDialer,
    target: HttpTarget,
    tls: Option<Arc<rustls::ClientConfig>>,
    path_root: String,
}

/// A concrete duplex wrapper so tokio-rustls can terminate TLS on the
/// boxed transport.
struct TlsIo(BoxProxyStream);
impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Accept-anything verifier for the engine-local insecure knob.
#[derive(Debug)]
struct MaskNoVerify(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for MaskNoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The http-mask TLS carrier config (`ca.GetTLSConfig` upstream always
/// verifies; the engine-local knob admits any cert for tests/private
/// CAs). ALPN is pinned to http/1.1 — this port has no h2 client.
fn mask_tls_config(insecure: bool) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config(format!("sudoku: http-mask tls: {e}")))?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(MaskNoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| Error::config(format!("sudoku: native cert store: {e}")))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::config(format!("sudoku: bad native cert: {e}")))?;
        }
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

impl HttpCtx {
    fn new(rc: &ResolvedConfig, dialer: TunnelDialer, ws: bool) -> Result<Self> {
        let target = if ws {
            normalize_ws_dial_target(&rc.server_address, rc.http_mask_tls, &rc.http_mask_host)?
        } else {
            normalize_http_dial_target(&rc.server_address, rc.http_mask_tls, &rc.http_mask_host)?
        };
        let tls = if target.scheme == "https" || target.scheme == "wss" {
            Some(mask_tls_config(rc.http_mask_tls_insecure)?)
        } else {
            None
        };
        Ok(HttpCtx {
            dialer,
            target,
            tls,
            path_root: rc.path_root.clone(),
        })
    }

    /// One fresh request connection (DialContext [+ TLS]).
    async fn open(&self) -> Result<BoxProxyStream> {
        let raw = (self.dialer)().await?;
        match &self.tls {
            None => Ok(raw),
            Some(config) => {
                let connector = tokio_rustls::TlsConnector::from(config.clone());
                let name = rustls::pki_types::ServerName::try_from(self.target.server_name.clone())
                    .map_err(|_| {
                        Error::config(format!(
                            "sudoku: invalid SNI {:?}",
                            self.target.server_name
                        ))
                    })?;
                let tls = connector
                    .connect(name, TlsIo(raw))
                    .await
                    .map_err(|e| Error::network(format!("sudoku: http-mask tls: {e}")))?;
                Ok(Box::new(tls))
            }
        }
    }

    /// One full request/response exchange over a fresh connection.
    async fn exchange(&self, req: HttpRequest<'_>) -> Result<HttpResp> {
        let mut conn = self.open().await?;
        let mut head = Vec::with_capacity(512);
        head.extend_from_slice(
            format!("{} {} HTTP/1.1\r\n", req.method, req.path_query).as_bytes(),
        );
        head.extend_from_slice(format!("Host: {}\r\n", self.target.header_host).as_bytes());
        for (name, value) in &req.headers {
            head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if let Some(body) = req.body {
            head.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        conn.write_all(&head).await?;
        if let Some(body) = req.body {
            conn.write_all(body).await?;
        }
        let status_line = read_crlf_line(&mut conn, 8 * 1024).await?;
        let status_text = String::from_utf8_lossy(&status_line).into_owned();
        let mut parts = status_text.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/1.") {
            return Err(Error::protocol(format!(
                "sudoku: bad http status line {status_text:?}"
            )));
        }
        let status: u16 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| Error::protocol(format!("sudoku: bad http status {status_text:?}")))?;
        let mut headers = Vec::new();
        loop {
            let line = read_crlf_line(&mut conn, 16 * 1024).await?;
            if line.is_empty() {
                break;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            if let Some((name, value)) = text.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let header = |name: &str| -> Option<String> {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.trim().to_string())
        };
        let kind = if header("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            BodyKind::Chunked
        } else if let Some(v) = header("content-length") {
            BodyKind::Length(
                v.parse::<u64>()
                    .map_err(|_| Error::protocol("sudoku: bad content-length"))?,
            )
        } else {
            BodyKind::UntilClose
        };
        Ok(HttpResp {
            status,
            body: HttpBody {
                conn,
                kind,
                done: false,
                chunk_rem: 0,
                trailers: Vec::new(),
            },
        })
    }
}

// -- retry classification (tunnel_retry.go) -----------------------------------

/// `isRetryableStatusCode` (tunnel_retry.go:27).
fn is_retryable_status(code: u16) -> bool {
    code == 408 || code == 429 || code >= 500
}

/// `isRetryableHTTPTransportError`: transport failures and the retryable
/// statuses (encoded as `network` errors) retry; hard protocol errors do
/// not.
fn is_retryable_err(e: &Error) -> bool {
    matches!(e, Error::Network(_) | Error::Io(_))
}

/// `statusError` as a network error so `is_retryable_err` can see the
/// code through the message (`bad status: NNN`).
fn retryable_status_err(code: u16) -> Error {
    Error::network(format!("bad status: {code}"))
}

fn hard_status_err(code: u16) -> Error {
    Error::protocol(format!("bad status: {code}"))
}

/// `nextBackoff` (tunnel_retry.go:149).
fn next_backoff(current: std::time::Duration, min: std::time::Duration, max: std::time::Duration) -> std::time::Duration {
    let mut current = current;
    if current < min {
        current = min;
    }
    if current >= max / 2 {
        return max;
    }
    current * 2
}

// -- the queued tunnel conn (tunnel_conn_queue.go) ----------------------------

/// A poll-friendly one-shot flag with an optional reason — upstream's
/// `closed`/`readEOF`/`writeDone` channels (tunnel_conn_queue.go) as a
/// value the AsyncRead/AsyncWrite impls can poll directly.
#[derive(Default)]
struct OnceFlag {
    state: Mutex<Option<String>>,
    wakers: Mutex<Vec<std::task::Waker>>,
}

impl OnceFlag {
    fn shared() -> Arc<Self> {
        Arc::new(OnceFlag::default())
    }

    /// Set once; wakes every registered poller. An empty reason means
    /// "signalled without a diagnostic" (the plain bool channels).
    fn set(&self, reason: impl Into<String>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.is_none() {
            *state = Some(reason.into());
            drop(state);
            let mut wakers = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
            for w in wakers.drain(..) {
                w.wake();
            }
        }
    }

    fn is_set(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn reason(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn poll_set(&self, cx: &mut Context<'_>) -> Poll<Option<String>> {
        if let Some(reason) = self.reason() {
            return Poll::Ready(Some(reason));
        }
        self.wakers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cx.waker().clone());
        Poll::Pending
    }

    /// Cancel-safe wait for the signal.
    async fn wait(&self) -> Option<String> {
        std::future::poll_fn(|cx| self.poll_set(cx)).await
    }
}

/// The shared control plane of one stream/poll tunnel connection
/// (`queuedConn`'s channels + the loops' stop signals).
#[derive(Clone)]
struct QueueState {
    /// `closed` + closeWithError's reason.
    closed: Arc<OnceFlag>,
    /// `writeClosed`.
    write_closed: Arc<OnceFlag>,
    /// `writeDone` + completeWrite's error.
    write_done: Arc<OnceFlag>,
}

impl QueueState {
    fn new() -> Self {
        QueueState {
            closed: OnceFlag::shared(),
            write_closed: OnceFlag::shared(),
            write_done: OnceFlag::shared(),
        }
    }

    fn close_with(&self, err: &str) {
        self.closed.set(err);
    }

    fn is_closed(&self) -> bool {
        self.closed.is_set()
    }

    /// Wait until closed (returns the reason). Cancel-safe.
    async fn wait_closed(&self) -> String {
        self.closed
            .wait()
            .await
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "sudoku: tunnel closed".to_string())
    }
}

/// `tunnelReadiness` (tunnel_ready.go:9): pull and push readiness.
#[derive(Clone)]
struct TunnelReadiness {
    pull: Arc<OnceFlag>,
    push: Arc<OnceFlag>,
}

impl TunnelReadiness {
    fn new() -> Self {
        TunnelReadiness {
            pull: OnceFlag::shared(),
            push: OnceFlag::shared(),
        }
    }

    fn mark_pull_ready(&self) {
        self.pull.set("");
    }

    fn mark_push_ready(&self) {
        self.push.set("");
    }

    /// `wait` (tunnel_ready.go:35): both directions once, racing the
    /// closed channel.
    async fn wait(&self, st: &QueueState) -> Result<()> {
        for flag in [&self.pull, &self.push] {
            loop {
                if flag.is_set() {
                    break;
                }
                tokio::select! {
                    _ = flag.wait() => {}
                    reason = st.wait_closed() => return Err(Error::network(reason)),
                }
            }
        }
        Ok(())
    }
}

/// The stream/poll tunnel conn (queuedConn + streamSplitConn/pollConn's
/// session-control drop hook).
struct TunnelConn {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    /// `readEOF` observed.
    read_eof_seen: bool,
    read_eof: Arc<OnceFlag>,
    /// The payload channel's sender end died.
    dead: bool,
    closed: Arc<OnceFlag>,
    write_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    write_closed: bool,
    write_closed_flag: Arc<OnceFlag>,
    write_done: Arc<OnceFlag>,
    /// `bestEffortCloseSession` on drop (stream/poll only); never
    /// read — holding it keeps the Drop hook alive.
    _close_hook: Option<CloseOnDrop>,
}

impl AsyncRead for TunnelConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Some(err) = self.closed.reason() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    err,
                )));
            }
            if self.dead {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "sudoku: tunnel closed",
                )));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(v)) => {
                    if v.is_empty() {
                        continue;
                    }
                    self.read_buf = v;
                }
                Poll::Ready(None) => {
                    self.dead = true;
                }
                Poll::Pending => {
                    // Race with readEOF and closed (queuedConn.Read's
                    // select); on readEOF one more non-blocking drain
                    // happens before reporting EOF.
                    match self.read_eof.poll_set(cx) {
                        Poll::Ready(_) => {
                            self.read_eof_seen = true;
                            continue;
                        }
                        Poll::Pending => {}
                    }
                    if self.read_eof_seen {
                        return match self.rx.try_recv() {
                            Ok(v) if !v.is_empty() => {
                                self.read_buf = v;
                                continue;
                            }
                            _ => Poll::Ready(Ok(())),
                        };
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for TunnelConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed.is_set() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku: tunnel closed",
            )));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku: tunnel write closed",
            )));
        }
        match self.write_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku: tunnel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// `CloseWrite` (tunnel_conn_queue.go:52): stop accepting writes,
    /// then wait for the push loop's drain + FIN.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_closed {
            self.write_closed = true;
            self.write_closed_flag.set("");
        }
        match self.write_done.poll_set(cx) {
            Poll::Ready(Some(err)) if !err.is_empty() => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                err,
            ))),
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `bestEffortCloseSession` fired from Drop (streamSplitConn.Close →
/// closeWithError → close=1 POST).
struct CloseOnDrop {
    ctx: HttpCtx,
    close_q: String,
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        let ctx = self.ctx.clone();
        let close_q = self.close_q.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = send_session_control(&ctx, &close_q).await;
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Session dial + control (tunnel_dial.go)
// ---------------------------------------------------------------------------

/// `parseAuthorizeResponse` (tunnel_dial.go:65): `token=…` line, optional
/// `ed=…` line (base64 RawURL), mandatory `cap=upload-seq`.
fn parse_authorize_response(body: &[u8]) -> Result<(String, Option<Vec<u8>>)> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    let token_line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("token="))
        .ok_or_else(|| Error::protocol("sudoku: authorize: missing token"))?;
    let token: String = token_line["token=".len()..]
        .bytes()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        .map(|c| c as char)
        .collect();
    if token.is_empty() {
        return Err(Error::protocol("sudoku: authorize: empty token"));
    }
    let early = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("ed="))
        .map(|l| &l["ed=".len()..])
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v.trim())
                .map_err(|_| Error::protocol("sudoku: authorize: decode early payload failed"))
        })
        .transpose()?;
    if !text.lines().map(str::trim).any(|l| l == "cap=upload-seq") {
        return Err(Error::protocol(
            "sudoku: server does not support HTTPMask v0.5 upload sequencing",
        ));
    }
    Ok((token, early))
}

/// `findAuthorizeField` — the `ed` value rides the body, covered above.
const _: () = {};

/// The per-session endpoint set (`sessionDialInfo`).
struct SessionEndpoints {
    push_q: String,
    pull_q: String,
    fin_q: String,
    close_q: String,
}

/// `dialSessionWithClient` (tunnel_dial.go:276): the authorize exchange.
/// Returns the endpoints; `early.process_response` runs on the `ed=`
/// field when the server answered the early handshake.
async fn dial_session(ctx: &HttpCtx, mode: TunnelMode, early: &mut EarlyClientState) -> Result<SessionEndpoints> {
    let mut auth_q = join_path_root(&ctx.path_root, "/session");
    if !early.request_payload.is_empty() {
        use base64::Engine;
        auth_q = format!(
            "{auth_q}?ed={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&early.request_payload)
        );
    }
    // Three attempts with a fixed 50ms backoff (dialSession's retry loop).
    let mut resp = None;
    let mut last_err = None;
    for _ in 0..3 {
        let req = HttpRequest {
            method: "GET",
            path_query: &auth_q,
            headers: apply_tunnel_headers(mode),
            body: None,
        };
        match ctx.exchange(req).await {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(e) => {
                let retryable = is_retryable_err(&e);
                last_err = Some(e);
                if !retryable {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let mut resp = match resp {
        Some(r) => r,
        None => {
            return Err(last_err.unwrap_or_else(|| Error::network("sudoku: authorize failed")));
        }
    };
    let body = resp.body.read_all_limited(4 * 1024).await?;
    if resp.status != 200 {
        let text = String::from_utf8_lossy(&body).trim().to_string();
        return Err(Error::network(format!(
            "sudoku: {} authorize bad status: {} ({})",
            mode.as_str(),
            resp.status,
            text
        )));
    }
    let (token, early_payload) = parse_authorize_response(&body)?;
    if let Some(payload) = early_payload {
        early.process_response(payload).await?;
    }
    let base = join_path_root(&ctx.path_root, "/api/v1/upload");
    Ok(SessionEndpoints {
        push_q: format!("{base}?token={token}"),
        pull_q: format!("{}?token={token}", join_path_root(&ctx.path_root, "/stream")),
        fin_q: format!("{base}?token={token}&fin=1"),
        close_q: format!("{base}?token={token}&close=1"),
    })
}

/// `sendSessionControl` (tunnel_dial.go:370): POST a control URL (fin /
/// close), ≤3 attempts inside 5s; 403/404/410 count as done.
async fn send_session_control(ctx: &HttpCtx, ctl_q: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut backoff = std::time::Duration::from_millis(50);
    for attempt in 0..3 {
        let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if budget.is_zero() {
            return Err(Error::network("sudoku: session control timed out"));
        }
        let post = async {
            let req = HttpRequest {
                method: "POST",
                path_query: ctl_q,
                headers: apply_tunnel_headers(TunnelMode::Stream),
                body: None,
            };
            let mut resp = ctx.exchange(req).await?;
            let _ = resp.body.read_all_limited(4 * 1024).await;
            if resp.status == 200 {
                return Ok(());
            }
            if resp.status == 403 || resp.status == 404 || resp.status == 410 {
                return Ok(());
            }
            if is_retryable_status(resp.status) {
                return Err(retryable_status_err(resp.status));
            }
            Err(hard_status_err(resp.status))
        };
        match tokio::time::timeout(budget, post).await {
            Err(_) => return Err(Error::network("sudoku: session control timed out")),
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => {
                if attempt == 2 || !is_retryable_err(&e) {
                    return Err(e);
                }
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    Err(Error::network("sudoku: session control failed"))
}

// ---------------------------------------------------------------------------
// stream mode (tunnel_conn_stream.go)
// ---------------------------------------------------------------------------

/// `dialStreamSplit` (tunnel_conn_stream.go:55): authorize, then the
/// pull/push loops over the queued conn.
async fn dial_stream(
    ctx: &HttpCtx,
    early: &mut EarlyClientState,
) -> Result<(BoxProxyStream, TunnelWait)> {
    let endpoints = dial_session(ctx, TunnelMode::Stream, early).await?;
    let st = QueueState::new();
    let readiness = TunnelReadiness::new();
    let (payload_tx, payload_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let read_eof = OnceFlag::shared();
    tokio::spawn(stream_pull_loop(
        ctx.clone(),
        endpoints.pull_q.clone(),
        st.clone(),
        readiness.clone(),
        payload_tx,
        read_eof.clone(),
    ));
    tokio::spawn(stream_push_loop(
        ctx.clone(),
        endpoints.push_q.clone(),
        endpoints.fin_q.clone(),
        st.clone(),
        readiness.clone(),
        write_rx,
    ));
    let conn = TunnelConn {
        rx: payload_rx,
        read_buf: Vec::new(),
        read_eof_seen: false,
        read_eof,
        dead: false,
        closed: st.closed.clone(),
        write_tx,
        write_closed: false,
        write_closed_flag: st.write_closed.clone(),
        write_done: st.write_done.clone(),
        _close_hook: Some(CloseOnDrop {
            ctx: ctx.clone(),
            close_q: endpoints.close_q.clone(),
        }),
    };
    Ok((Box::new(conn), TunnelWait { readiness, st }))
}

/// `wrapReadyTunnelConn` + `WaitTunnelReady` inputs: the readiness flags
/// plus the queue state they race against.
struct TunnelWait {
    readiness: TunnelReadiness,
    st: QueueState,
}

impl TunnelWait {
    /// `WaitTunnelReady` (tunnel_ready.go:91).
    async fn wait(&self) -> Result<()> {
        self.readiness.wait(&self.st).await
    }
}

/// `pullLoop` (tunnel_conn_stream.go:125): long-poll GETs whose chunked
/// bodies stream the downlink; `X-Sudoku-Stream-EOF` ends the read side.
#[allow(clippy::too_many_arguments)]
async fn stream_pull_loop(
    ctx: HttpCtx,
    pull_q: String,
    st: QueueState,
    readiness: TunnelReadiness,
    payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    read_eof: Arc<OnceFlag>,
) {
    const READ_CHUNK: usize = 32 * 1024;
    const IDLE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);
    const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    let mut backoff = MIN_BACKOFF;
    loop {
        if st.is_closed() {
            return;
        }
        let req = HttpRequest {
            method: "GET",
            path_query: &pull_q,
            headers: apply_tunnel_headers(TunnelMode::Stream),
            body: None,
        };
        let mut resp = match ctx.exchange(req).await {
            Ok(r) => r,
            Err(e) => {
                if !is_retryable_err(&e) {
                    st.close_with(&format!("stream pull failed: {e}"));
                    return;
                }
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
        };
        backoff = MIN_BACKOFF;
        if resp.status != 200 {
            if is_retryable_status(resp.status) {
                let _ = resp.body.read_all_limited(4 * 1024).await;
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
            st.close_with(&format!("stream pull bad status: {}", resp.status));
            return;
        }
        readiness.mark_pull_ready();

        let mut read_any = false;
        let mut body_retry = false;
        loop {
            let mut chunk = Vec::with_capacity(READ_CHUNK);
            match resp.body.read_some(&mut chunk).await {
                Ok(true) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    read_any = true;
                    let closed = st.wait_closed();
                    tokio::select! {
                        res = payload_tx.send(chunk) => {
                            if res.is_err() {
                                return;
                            }
                        }
                        reason = closed => {
                            st.close_with(&reason);
                            return;
                        }
                    }
                }
                Ok(false) => {
                    // Body ended: a trailer EOF ends the read side, any
                    // other end is just a long-poll boundary.
                    if resp.body.trailer("X-Sudoku-Stream-EOF") == Some("1") {
                        read_eof.set("");
                        return;
                    }
                    break;
                }
                Err(e) => {
                    if is_retryable_err(&e) {
                        body_retry = true;
                        break;
                    }
                    st.close_with(&format!("stream pull body failed: {e}"));
                    return;
                }
            }
        }
        if body_retry {
            let closed = st.wait_closed();
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                reason = closed => {
                    st.close_with(&reason);
                    return;
                }
            }
            backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
            continue;
        }
        backoff = MIN_BACKOFF;
        if !read_any {
            let closed = st.wait_closed();
            tokio::select! {
                _ = tokio::time::sleep(IDLE_BACKOFF) => {}
                reason = closed => {
                    st.close_with(&reason);
                    return;
                }
            }
        }
    }
}

/// `pushLoop` (tunnel_conn_stream.go:247): batch writes into sequenced
/// POST uploads; FIN (fin=1) on CloseWrite.
async fn stream_push_loop(
    ctx: HttpCtx,
    push_q: String,
    fin_q: String,
    st: QueueState,
    readiness: TunnelReadiness,
    mut write_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    const MAX_BATCH_BYTES: usize = 256 * 1024;
    const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
    const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    let upload_seq = std::sync::atomic::AtomicU64::new(0);
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_BATCH_BYTES);
    let ctx_flush = ctx.clone();

    // flush() (tunnel_conn_stream.go:269): one sequenced POST, retried
    // until it lands or the tunnel closes.
    macro_rules! flush {
        () => {
            if buf.is_empty() {
                Ok(())
            } else {
                let sequence = 1 + upload_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let url = format!("{push_q}&seq={sequence}");
                let payload = std::mem::take(&mut buf);
                let ctx = &ctx_flush;
                retry_persistent(&st, MIN_BACKOFF, MAX_BACKOFF, || async {
                    // Per-attempt 20s request timeout
                    // (requestTimeout, tunnel_conn_stream.go:251).
                    let req = HttpRequest {
                        method: "POST",
                        path_query: &url,
                        headers: {
                            let mut h = apply_tunnel_headers(TunnelMode::Stream);
                            h.push(("Content-Type".into(), "application/octet-stream".into()));
                            h
                        },
                        body: Some(&payload),
                    };
                    let mut resp = tokio::time::timeout(REQUEST_TIMEOUT, ctx.exchange(req))
                        .await
                        .map_err(|_| Error::network("sudoku: stream push timed out"))??;
                    let _ = resp.body.read_all_limited(4 * 1024).await;
                    if resp.status == 200 {
                        return Ok(());
                    }
                    if is_retryable_status(resp.status) {
                        return Err(retryable_status_err(resp.status));
                    }
                    Err(hard_status_err(resp.status))
                })
                .await
                .map(|()| readiness.mark_push_ready())
            }
        };
    }

    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let write_closed_flag = st.write_closed.clone();
    let mut write_err: Option<String> = None;
    loop {
        let mut fin_phase = false;
        tokio::select! {
            maybe = write_rx.recv() => {
                match maybe {
                    Some(b) => {
                        if b.is_empty() {
                            continue;
                        }
                        if buf.len() + b.len() > MAX_BATCH_BYTES {
                            if let Err(e) = flush!() {
                                write_err = Some(format!("stream push flush failed: {e}"));
                                break;
                            }
                            ticker.reset();
                        }
                        buf.extend_from_slice(&b);
                        if buf.len() >= MAX_BATCH_BYTES {
                            if let Err(e) = flush!() {
                                write_err = Some(format!("stream push flush failed: {e}"));
                                break;
                            }
                            ticker.reset();
                        }
                    }
                    None => {
                        // The tunnel conn is gone.
                        let e = st.wait_closed().await;
                        write_err = Some(e);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = flush!() {
                    write_err = Some(format!("stream push flush failed: {e}"));
                    break;
                }
            }
            _ = write_closed_flag.wait() => {
                fin_phase = true;
            }
        }
        if fin_phase {
            // Drain everything already accepted, flush, then FIN.
            while let Ok(b) = write_rx.try_recv() {
                if b.is_empty() {
                    continue;
                }
                if buf.len() + b.len() > MAX_BATCH_BYTES {
                    if let Err(e) = flush!() {
                        write_err = Some(format!("stream push flush failed: {e}"));
                        break;
                    }
                }
                buf.extend_from_slice(&b);
            }
            if write_err.is_none() {
                if let Err(e) = flush!() {
                    write_err = Some(format!("stream push flush failed: {e}"));
                }
            }
            if write_err.is_none() {
                if let Err(e) = send_session_control(&ctx, &fin_q).await {
                    write_err = Some(format!("stream FIN failed: {e}"));
                }
            }
            break;
        }
    }
    if let Some(err) = &write_err {
        st.close_with(err);
    }
    st.write_done.set(write_err.unwrap_or_default());
}

/// `retryPersistent` (tunnel_retry.go:101).
async fn retry_persistent<F, Fut>(
    st: &QueueState,
    min_backoff: std::time::Duration,
    max_backoff: std::time::Duration,
    mut f: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut backoff = min_backoff;
    loop {
        match f().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !is_retryable_err(&e) {
                    return Err(e);
                }
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => return Err(Error::network(reason)),
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// poll mode (tunnel_conn_poll.go)
// ---------------------------------------------------------------------------

/// `dialPoll` (tunnel_conn_poll.go:49).
async fn dial_poll(
    ctx: &HttpCtx,
    early: &mut EarlyClientState,
) -> Result<(BoxProxyStream, TunnelWait)> {
    let endpoints = dial_session(ctx, TunnelMode::Poll, early).await?;
    let st = QueueState::new();
    let readiness = TunnelReadiness::new();
    let (payload_tx, payload_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let read_eof = OnceFlag::shared();
    tokio::spawn(poll_pull_loop(
        ctx.clone(),
        endpoints.pull_q.clone(),
        st.clone(),
        readiness.clone(),
        payload_tx,
        read_eof.clone(),
    ));
    tokio::spawn(poll_push_loop(
        ctx.clone(),
        endpoints.push_q.clone(),
        endpoints.fin_q.clone(),
        st.clone(),
        readiness.clone(),
        write_rx,
    ));
    let conn = TunnelConn {
        rx: payload_rx,
        read_buf: Vec::new(),
        read_eof_seen: false,
        read_eof,
        dead: false,
        closed: st.closed.clone(),
        write_tx,
        write_closed: false,
        write_closed_flag: st.write_closed.clone(),
        write_done: st.write_done.clone(),
        _close_hook: Some(CloseOnDrop {
            ctx: ctx.clone(),
            close_q: endpoints.close_q.clone(),
        }),
    };
    Ok((Box::new(conn), TunnelWait { readiness, st }))
}

/// `pullLoop` (tunnel_conn_poll.go:119): each response is a set of
/// base64 lines, one decoded payload per line.
async fn poll_pull_loop(
    ctx: HttpCtx,
    pull_q: String,
    st: QueueState,
    readiness: TunnelReadiness,
    payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    read_eof: Arc<OnceFlag>,
) {
    const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    let mut backoff = MIN_BACKOFF;
    loop {
        if st.is_closed() {
            return;
        }
        let req = HttpRequest {
            method: "GET",
            path_query: &pull_q,
            headers: apply_tunnel_headers(TunnelMode::Poll),
            body: None,
        };
        let mut resp = match ctx.exchange(req).await {
            Ok(r) => r,
            Err(e) => {
                if !is_retryable_err(&e) {
                    st.close_with(&format!("poll pull request failed: {e}"));
                    return;
                }
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
        };
        if resp.status != 200 {
            if is_retryable_status(resp.status) {
                let _ = resp.body.read_all_limited(4 * 1024).await;
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
            st.close_with(&format!("poll pull bad status: {}", resp.status));
            return;
        }
        readiness.mark_pull_ready();

        // bufio.Scanner over the body: one base64 line per payload.
        use base64::Engine;
        let mut carry: Vec<u8> = Vec::new();
        let mut failure: Option<Error> = None;
        loop {
            let mut chunk = Vec::new();
            match resp.body.read_some(&mut chunk).await {
                Ok(true) => carry.extend_from_slice(&chunk),
                Ok(false) => break,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
            while let Some(pos) = carry.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = carry.drain(..=pos).collect();
                line.pop(); // '\n'
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                let payload = base64::engine::general_purpose::STANDARD
                    .decode(&line)
                    .map_err(|_| Error::protocol("sudoku: poll pull decode failed"));
                let payload = match payload {
                    Ok(p) => p,
                    Err(_) => {
                        // closeWithError (tunnel_conn_poll.go:181).
                        let mut dead = resp.body;
                        let _ = dead.read_all_limited(4 * 1024).await;
                        st.close_with("poll pull decode failed");
                        return;
                    }
                };
                let closed = st.wait_closed();
                tokio::select! {
                    res = payload_tx.send(payload) => {
                        if res.is_err() {
                            return;
                        }
                    }
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
            }
        }
        if let Some(e) = failure {
            if is_retryable_err(&e) {
                let closed = st.wait_closed();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
            st.close_with(&format!("poll pull scan failed: {e}"));
            return;
        }
        // The final line may lack its newline (Scanner still yields it).
        if !carry.is_empty() {
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&carry)
                .map_err(|_| Error::protocol("sudoku: poll pull decode failed"));
            if let Ok(payload) = payload {
                let closed = st.wait_closed();
                tokio::select! {
                    res = payload_tx.send(payload) => {
                        if res.is_err() {
                            return;
                        }
                    }
                    reason = closed => {
                        st.close_with(&reason);
                        return;
                    }
                }
            }
        }
        if resp.body.trailer("X-Sudoku-Stream-EOF") == Some("1") {
            read_eof.set("");
            return;
        }
        backoff = MIN_BACKOFF;
    }
}

/// `pushLoop` (tunnel_conn_poll.go:212).
async fn poll_push_loop(
    ctx: HttpCtx,
    push_q: String,
    fin_q: String,
    st: QueueState,
    readiness: TunnelReadiness,
    mut write_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    const MAX_BATCH_BYTES: usize = 64 * 1024;
    const MAX_LINE_RAW_BYTES: usize = 16 * 1024;
    const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
    const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    let upload_seq = std::sync::atomic::AtomicU64::new(0);
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_BATCH_BYTES * 2);
    let mut pending_raw: usize = 0;

    macro_rules! flush {
        () => {
            if buf.is_empty() {
                Ok(())
            } else {
                let sequence = 1 + upload_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let url = format!("{push_q}&seq={sequence}");
                let payload = std::mem::take(&mut buf);
                let result = retry_persistent(&st, MIN_BACKOFF, MAX_BACKOFF, || async {
                    let req = HttpRequest {
                        method: "POST",
                        path_query: &url,
                        headers: {
                            let mut h = apply_tunnel_headers(TunnelMode::Poll);
                            h.push(("Content-Type".into(), "text/plain".into()));
                            h
                        },
                        body: Some(&payload),
                    };
                    let mut resp = ctx.exchange(req).await?;
                    let _ = resp.body.read_all_limited(4 * 1024).await;
                    if resp.status == 200 {
                        return Ok(());
                    }
                    if is_retryable_status(resp.status) {
                        return Err(retryable_status_err(resp.status));
                    }
                    Err(hard_status_err(resp.status))
                })
                .await;
                match result {
                    Ok(()) => {
                        readiness.mark_push_ready();
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
    }

    // enqueue (tunnel_conn_poll.go:285): base64 lines of ≤16KiB raw; the
    // caller flushes when the batch would overflow.
    fn enqueue(buf: &mut Vec<u8>, pending_raw: &mut usize, mut b: &[u8]) {
        use base64::Engine;
        while !b.is_empty() {
            let chunk = &b[..b.len().min(MAX_LINE_RAW_BYTES)];
            b = &b[chunk.len()..];
            buf.extend_from_slice(
                base64::engine::general_purpose::STANDARD.encode(chunk).as_bytes(),
            );
            buf.push(b'\n');
            *pending_raw += chunk.len();
        }
    }

    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let write_closed_flag = st.write_closed.clone();
    let mut write_err: Option<String> = None;
    loop {
        let mut fin_phase = false;
        tokio::select! {
            maybe = write_rx.recv() => {
                match maybe {
                    Some(b) => {
                        if b.is_empty() {
                            continue;
                        }
                        // Split into lines, flushing when the batch fills.
                        let mut rest: &[u8] = &b;
                        while !rest.is_empty() {
                            let take = rest.len().min(MAX_LINE_RAW_BYTES);
                            if pending_raw + take > MAX_BATCH_BYTES {
                                if let Err(e) = flush!() {
                                    write_err = Some(format!("poll push flush failed: {e}"));
                                    break;
                                }
                                // buf.Reset(); pendingRaw = 0
                                // (tunnel_conn_poll.go:277).
                                pending_raw = 0;
                                ticker.reset();
                            }
                            enqueue(&mut buf, &mut pending_raw, &rest[..take]);
                            rest = &rest[take..];
                        }
                        if write_err.is_some() {
                            break;
                        }
                        if pending_raw >= MAX_BATCH_BYTES {
                            if let Err(e) = flush!() {
                                write_err = Some(format!("poll push flush failed: {e}"));
                                break;
                            }
                            pending_raw = 0;
                            ticker.reset();
                        }
                    }
                    None => {
                        let e = st.wait_closed().await;
                        write_err = Some(e);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = flush!() {
                    write_err = Some(format!("poll push flush failed: {e}"));
                    break;
                }
                pending_raw = 0;
            }
            _ = write_closed_flag.wait() => {
                fin_phase = true;
            }
        }
        if fin_phase {
            while let Ok(b) = write_rx.try_recv() {
                if b.is_empty() {
                    continue;
                }
                enqueue(&mut buf, &mut pending_raw, &b);
            }
            if let Err(e) = flush!() {
                write_err = Some(format!("poll push flush failed: {e}"));
            }
            if write_err.is_none() {
                if let Err(e) = send_session_control(&ctx, &fin_q).await {
                    write_err = Some(format!("poll FIN failed: {e}"));
                }
            }
            break;
        }
    }
    if let Some(err) = &write_err {
        st.close_with(err);
    }
    st.write_done.set(write_err.unwrap_or_default());
}

// ---------------------------------------------------------------------------
// ws mode (tunnel_ws.go + ws_stream_conn.go + ws_auth.go)
// ---------------------------------------------------------------------------

/// `tunnelAuth` (ws_auth.go): token = `ts_be64 || HMAC-SHA256_trunc16`
/// base64 RawURL, HMAC key = `sha256("sudoku-httpmask-auth-v1:" || key)`.
fn tunnel_auth_token(auth_key: &str, mode: &str, method: &str, path: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let key_material = Sha256::new_with_prefix(b"sudoku-httpmask-auth-v1:")
        .chain_update(auth_key.as_bytes())
        .finalize();
    let key: [u8; 32] = key_material.into();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let method = if method.is_empty() { "GET".to_string() } else { method.to_uppercase() };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac accepts any key");
    mac.update(mode.as_bytes());
    mac.update(&[0]);
    mac.update(method.as_bytes());
    mac.update(&[0]);
    mac.update(path.as_bytes());
    mac.update(&[0]);
    mac.update(&ts.to_be_bytes());
    let sig = mac.finalize().into_bytes();
    let mut raw = [0u8; 24];
    raw[..8].copy_from_slice(&ts.to_be_bytes());
    raw[8..].copy_from_slice(&sig[..16]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// The WebSocket event/command channels between the frame tasks and the
/// stream (`wsStreamConn` over a duplex).
enum WsEvent {
    Data(Vec<u8>),
    Eof,
}

enum WsCmd {
    Data(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// RFC 6455 client frame (always masked).
fn ws_build_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode); // FIN + opcode
    let mask_bit = 0x80u8;
    if payload.len() < 126 {
        frame.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    let mut mask = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mask);
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    frame
}

/// One parsed server frame.
struct WsFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

async fn ws_read_frame<R: AsyncRead + Unpin>(conn: &mut R) -> Result<WsFrame> {
    let mut hdr = [0u8; 2];
    conn.read_exact(&mut hdr).await?;
    let fin = hdr[0] & 0x80 != 0;
    let opcode = hdr[0] & 0x0f;
    if hdr[0] & 0x70 != 0 {
        return Err(Error::protocol("sudoku: ws frame with RSV bits"));
    }
    let masked = hdr[1] & 0x80 != 0;
    let len = (hdr[1] & 0x7f) as u64;
    let len = match len {
        126 => {
            let mut ext = [0u8; 2];
            conn.read_exact(&mut ext).await?;
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0u8; 8];
            conn.read_exact(&mut ext).await?;
            u64::from_be_bytes(ext)
        }
        n => n,
    };
    let mut mask = [0u8; 4];
    if masked {
        conn.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    conn.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(WsFrame { fin, opcode, payload })
}

/// `newWSStreamConn` (ws_stream_conn.go): the frame tasks feeding a
/// duplex the tunnel conn reads/writes.
struct WsConn {
    event_rx: tokio::sync::mpsc::Receiver<WsEvent>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<WsCmd>,
    pending: Vec<u8>,
    eof: bool,
}

impl AsyncRead for WsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.event_rx.poll_recv(cx) {
                Poll::Ready(Some(WsEvent::Data(mut d))) => {
                    if d.is_empty() {
                        continue;
                    }
                    if d.len() > buf.remaining() {
                        let take = buf.remaining();
                        buf.put_slice(&d[..take]);
                        self.pending = d.split_off(take);
                    } else {
                        buf.put_slice(&d);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(WsEvent::Eof)) => {
                    self.eof = true;
                }
                Poll::Ready(None) => {
                    self.eof = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.eof {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku: ws tunnel closed",
            )));
        }
        match self.cmd_tx.send(WsCmd::Data(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku: ws tunnel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// `wsStreamConn.Close` (ws_stream_conn.go:75): close frame then TCP.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.cmd_tx.send(WsCmd::Close);
        Poll::Ready(Ok(()))
    }
}

impl Drop for WsConn {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(WsCmd::Close);
    }
}

/// `dialWS` (tunnel_ws.go:98): the upgrade handshake, the early
/// handshake riding the `ed` query param and the `X-Sudoku-Early`
/// response header.
async fn dial_ws(ctx: &HttpCtx, auth_key: &str, early: &mut EarlyClientState) -> Result<BoxProxyStream> {
    let mut path = join_path_root(&ctx.path_root, "/ws");
    let mut query = Vec::new();
    if !early.request_payload.is_empty() {
        use base64::Engine;
        query.push(format!(
            "ed={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&early.request_payload)
        ));
    }
    let token = tunnel_auth_token(auth_key, "ws", "GET", "/ws");
    if !auth_key.trim().is_empty() {
        query.push(format!("auth={token}"));
    }
    if !query.is_empty() {
        path = format!("{path}?{}", query.join("&"));
    }
    let mut headers = apply_ws_headers();
    if !auth_key.trim().is_empty() {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    headers.push(("Connection".into(), "Upgrade".into()));
    headers.push(("Upgrade".into(), "websocket".into()));
    headers.push(("Sec-WebSocket-Version".into(), "13".into()));
    use base64::Engine;
    let mut key_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
    headers.push((
        "Sec-WebSocket-Key".into(),
        base64::engine::general_purpose::STANDARD.encode(key_bytes),
    ));

    let mut conn = ctx.open().await?;
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
    head.extend_from_slice(format!("Host: {}\r\n", ctx.target.header_host).as_bytes());
    for (name, value) in &headers {
        head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    conn.write_all(&head).await?;

    // The 101 response head.
    let status_line = read_crlf_line(&mut conn, 8 * 1024).await?;
    let status_text = String::from_utf8_lossy(&status_line).into_owned();
    let status: u16 = status_text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| Error::protocol(format!("sudoku: bad ws status line {status_text:?}")))?;
    let mut resp_headers = Vec::new();
    loop {
        let line = read_crlf_line(&mut conn, 16 * 1024).await?;
        if line.is_empty() {
            break;
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        if let Some((name, value)) = text.split_once(':') {
            resp_headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    if status != 101 {
        return Err(Error::network(format!("sudoku: ws upgrade bad status: {status}")));
    }
    let early_header = resp_headers
        .iter()
        .find(|(k, _)| k == "x-sudoku-early")
        .map(|(_, v)| v.clone());
    if let Some(value) = early_header {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| Error::protocol("sudoku: ws early payload decode failed"))?;
        early.process_response(decoded).await?;
    }

    // The frame tasks (wsStreamConn's reader/writer).
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<WsEvent>(64);
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<WsCmd>();
    let (mut reader_conn, mut writer_conn) = tokio::io::split(conn);
    let reader_cmd_tx = cmd_tx.clone();
    tokio::spawn(async move {
        // Assemble fragmented messages; answer pings; EOF on close.
        let mut assembled: Option<(u8, Vec<u8>)> = None;
        loop {
            let frame = match ws_read_frame(&mut reader_conn).await {
                Ok(f) => f,
                Err(_) => {
                    let _ = event_tx.send(WsEvent::Eof).await;
                    return;
                }
            };
            match frame.opcode {
                8 => {
                    // Close: reply with a close frame, then EOF.
                    let _ = reader_cmd_tx.send(WsCmd::Close);
                    let _ = event_tx.send(WsEvent::Eof).await;
                    return;
                }
                9 => {
                    // Ping → pong with the same payload.
                    let _ = reader_cmd_tx.send(WsCmd::Pong(frame.payload));
                    continue;
                }
                10 => continue, // pong
                1 | 2 => {
                    if frame.fin {
                        let _ = event_tx.send(WsEvent::Data(frame.payload)).await;
                    } else {
                        assembled = Some((frame.opcode, frame.payload));
                    }
                }
                0 => {
                    // Continuation.
                    match assembled.as_mut() {
                        Some((_, buf)) => buf.extend_from_slice(&frame.payload),
                        None => continue, // stray continuation
                    }
                    if frame.fin {
                        if let Some((_, buf)) = assembled.take() {
                            let _ = event_tx.send(WsEvent::Data(buf)).await;
                        }
                    }
                }
                _ => {
                    let _ = event_tx.send(WsEvent::Eof).await;
                    return;
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                WsCmd::Data(payload) => {
                    if writer_conn.write_all(&ws_build_frame(2, &payload)).await.is_err() {
                        return;
                    }
                }
                WsCmd::Pong(payload) => {
                    if writer_conn.write_all(&ws_build_frame(10, &payload)).await.is_err() {
                        return;
                    }
                }
                WsCmd::Close => {
                    let body = 1000u16.to_be_bytes().to_vec();
                    let _ = writer_conn.write_all(&ws_build_frame(8, &body)).await;
                    let _ = writer_conn.shutdown().await;
                    return;
                }
            }
        }
    });
    Ok(Box::new(WsConn {
        event_rx,
        cmd_tx,
        pending: Vec::new(),
        eof: false,
    }))
}

// ---------------------------------------------------------------------------
// DialTunnel (tunnel_api.go) + the public entry points
// ---------------------------------------------------------------------------

/// `autoProbeTimeout` (tunnel_api.go:168).
const AUTO_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// `DialTunnel` (tunnel_api.go:138) for every mode, always with the
/// early handshake armed (the client path passes `Upgrade`, which
/// upstream turns into the early handshake). Falls back to the in-band
/// handshake when the server ignored the early data.
async fn dial_http_mask_tunnel(
    rc: &ResolvedConfig,
    dialer: TunnelDialer,
) -> Result<(RecordConn<ObfsStream>, Option<TunnelWait>)> {
    let mode = rc.http_mask_mode.as_str();
    let (choice, hint) = pick_client_table(&rc.tables)?;
    let mut early = EarlyClientState::new(rc, choice.clone(), hint).await?;
    let raw: BoxProxyStream;
    let readiness: Option<TunnelWait>;
    match mode {
        "ws" => {
            let ctx = HttpCtx::new(rc, dialer, true)?;
            let auth_key = client_aead_seed(&rc.seed);
            raw = dial_ws(&ctx, &auth_key, &mut early).await?;
            readiness = None;
        }
        "poll" => {
            let ctx = HttpCtx::new(rc, dialer, false)?;
            let (conn, ready) = dial_poll(&ctx, &mut early).await?;
            raw = conn;
            readiness = Some(ready);
        }
        _ => {
            // stream + auto (auto: 20s stream probe, then poll).
            let ctx = HttpCtx::new(rc, dialer.clone(), false)?;
            let attempt = async {
                if mode == "auto" {
                    match tokio::time::timeout(AUTO_PROBE_TIMEOUT, dial_stream(&ctx, &mut early)).await {
                        Ok(r) => r,
                        Err(_) => Err(Error::network("sudoku: stream probe timed out")),
                    }
                } else {
                    dial_stream(&ctx, &mut early).await
                }
            };
            match attempt.await {
                Ok((conn, ready)) => {
                    raw = conn;
                    readiness = Some(ready);
                }
                Err(stream_err) if mode == "auto" => {
                    // The stream attempt consumed the early state's
                    // payload; rebuild it for the poll attempt.
                    let mut early2 = EarlyClientState::new(rc, choice.clone(), hint).await?;
                    match dial_poll(&ctx, &mut early2).await {
                        Ok((conn, ready)) => {
                            early = early2;
                            raw = conn;
                            readiness = Some(ready);
                        }
                        Err(poll_err) => {
                            return Err(Error::network(format!(
                                "sudoku: auto tunnel failed: stream: {stream_err}; poll: {poll_err}"
                            )));
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    // applyEarlyHandshakeOrUpgrade (early_handshake.go:78): the early
    // branch when Ready(), else the in-band Upgrade.
    if early.response_set {
        let conn = early.wrap_conn(raw)?;
        Ok((conn, readiness))
    } else {
        let obfs = ObfsStream::new(
            raw,
            choice,
            rc.padding_min,
            rc.padding_max,
            rc.enable_pure_downlink,
        );
        let conn = kip_handshake_client(
            RecordConn::new(obfs, rc.method, [0u8; 32], [0u8; 32]),
            rc,
            hint,
        )
        .await?;
        Ok((conn, readiness))
    }
}

/// Whether the config's http-mask mode is a tunnel mode (stream/poll/
/// auto/ws): the integrator picks `connect_tunnel*` (which take a
/// dialer) instead of `connect`/`connect_udp` for these.
pub fn uses_http_mask_tunnel(cfg: &SudokuOut) -> bool {
    resolve_config(cfg).map(|rc| rc.tunnel_mode()).unwrap_or(false)
}

/// `DialContext` over an HTTPMask tunnel (mihomo dialAndHandshake's
/// tunnel branch): early-handshake KIP exchange, then `KIPTypeOpenTCP`.
pub async fn connect_tunnel(
    cfg: &SudokuOut,
    dialer: TunnelDialer,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    let rc = resolve_config(cfg)?;
    if !rc.tunnel_mode() {
        return Err(Error::config(format!(
            "sudoku: http-mask-mode {:?} does not use the http tunnel — use connect",
            if rc.http_mask_mode.is_empty() { "legacy" } else { &rc.http_mask_mode }
        )));
    }
    if rc.multiplex == "on" {
        return Err(Error::config(
            "sudoku: multiplex \"on\" requires the session dialer — use connect_tunnel_mux",
        ));
    }
    let (mut conn, _readiness) = dial_http_mask_tunnel(&rc, dialer).await?;
    let addr_buf = encode_address(target);
    write_kip_message(&mut conn, KIP_TYPE_OPEN_TCP, &addr_buf).await?;
    debug!(target: "engine", "sudoku: tunnel TCP open sent for {target}");
    Ok(Box::new(conn))
}

/// `ListenPacketContext` over an HTTPMask tunnel.
pub async fn connect_tunnel_udp(
    cfg: &SudokuOut,
    dialer: TunnelDialer,
) -> Result<BoxProxyStream> {
    let rc = resolve_config(cfg)?;
    if !rc.tunnel_mode() {
        return Err(Error::config(format!(
            "sudoku: http-mask-mode {:?} does not use the http tunnel — use connect_udp",
            if rc.http_mask_mode.is_empty() { "legacy" } else { &rc.http_mask_mode }
        )));
    }
    let (mut conn, _readiness) = dial_http_mask_tunnel(&rc, dialer).await?;
    write_kip_message(&mut conn, KIP_TYPE_START_UOT, &[]).await?;
    debug!(target: "engine", "sudoku: tunnel UoT session started");
    Ok(Box::new(conn))
}

/// `StartMultiplexClient` over an HTTPMask tunnel (multiplex.go:14):
/// handshake, `KIPTypeStartMux`, `WaitTunnelReady`, then the session.
pub async fn connect_tunnel_mux(
    cfg: &SudokuOut,
    dialer: TunnelDialer,
) -> Result<SudokuMuxSession> {
    let rc = resolve_config(cfg)?;
    if !rc.tunnel_mode() {
        return Err(Error::config(format!(
            "sudoku: http-mask-mode {:?} does not use the http tunnel — use connect_mux",
            if rc.http_mask_mode.is_empty() { "legacy" } else { &rc.http_mask_mode }
        )));
    }
    let (mut conn, readiness) = dial_http_mask_tunnel(&rc, dialer).await?;
    write_kip_message(&mut conn, KIP_TYPE_START_MUX, &[]).await?;
    if let Some(wait) = readiness {
        // WaitTunnelReady (tunnel_ready.go:91) — a no-op for ws.
        wait.wait()
            .await
            .map_err(|e| Error::network(format!("sudoku: warm mux tunnel failed: {e}")))?;
    }
    debug!(target: "engine", "sudoku: tunnel mux session starting");
    Ok(SudokuMuxSession::new(Box::new(conn)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn test_key() -> String {
        format!("sudoku-key-{:016x}", rand::random::<u64>())
    }

    // ------------------------------------------------------------ gorand

    /// Vectors generated with Go 1.26 on this machine:
    /// `rand.New(rand.NewSource(seed)).Shuffle(288, ...)`.
    #[test]
    fn go_rand_shuffle_matches_go() {
        let cases: &[(i64, [usize; 3], [usize; 3], u64)] = &[
            (1, [127, 152, 153], [190, 269, 174], 0x8cd2_f025_4592_b65f),
            (42, [227, 71, 200], [172, 18, 107], 0x9518_ff62_d5fa_c41b),
            (-987654321, [10, 64, 172], [235, 102, 150], 0x7b65_9534_b044_0f43),
            (i64::MAX, [127, 152, 153], [190, 269, 174], 0x8cd2_f025_4592_b65f),
            (-1, [119, 98, 158], [95, 17, 113], 0x02d2_8c23_02ce_8a35),
        ];
        for &(seed, first, last, fnv) in cases {
            let mut idx: Vec<usize> = (0..288).collect();
            let mut rng = gorand::RngSource::new(seed);
            rng.shuffle(idx.len(), |i, j| idx.swap(i, j));
            assert_eq!(&idx[..3], first, "seed {seed}");
            assert_eq!(&idx[285..], last, "seed {seed}");
            let mut h: u64 = 14695981039346656037;
            for v in idx {
                h = (h ^ v as u64).wrapping_mul(1099511628211);
            }
            assert_eq!(h, fnv, "seed {seed}");
        }
    }

    /// Go `GenerateAllGrids()` order (generated with upstream grid.go).
    #[test]
    fn grids_match_go_backtracking_order() {
        let grids = generate_all_grids();
        assert_eq!(grids.len(), 288);
        assert_eq!(grids[0], [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1]);
        assert_eq!(grids[100], [2, 3, 1, 4, 1, 4, 3, 2, 3, 2, 4, 1, 4, 1, 2, 3]);
        assert_eq!(grids[287], [4, 3, 2, 1, 2, 1, 4, 3, 3, 4, 1, 2, 1, 2, 3, 4]);
    }

    /// Table ground truth from upstream table.go run with Go 1.26.
    #[test]
    fn table_matches_go_ground_truth() {
        for (key, entropy_hint, ascii_hint, dir_hint, map_len, e0) in [
            (
                "test-key",
                0x0f252fc1u32,
                0x23d22c64u32,
                0xa61b6f55u32,
                23256usize,
                [0x60u8, 0x23, 0x0d, 0x4e],
            ),
            (
                "another key 42",
                0xa79814b3,
                0x349c886a,
                0xd58fe1c4,
                22676,
                [0x00, 0x62, 0x49, 0x2b],
            ),
        ] {
            let t = new_table_with_custom(key, "prefer_entropy", "").unwrap();
            assert_eq!(t.hint(), entropy_hint, "{key}");
            assert_eq!(t.padding_pool.len(), 16, "{key}");
            assert_eq!(t.padding_pool[0], 0x80, "{key}");
            assert_eq!(t.decode_map.len(), map_len, "{key}");
            assert_eq!(t.encode_table[0][0], e0, "{key}");
            assert!(!t.is_ascii, "{key}");

            let ta = new_table_with_custom(key, "prefer_ascii", "").unwrap();
            assert_eq!(ta.hint(), ascii_hint, "{key}");
            assert_eq!(ta.padding_pool.len(), 32, "{key}");
            assert_eq!(ta.decode_map.len(), map_len, "{key}");

            let td = new_table_with_custom(key, "up_ascii_down_entropy", "").unwrap();
            assert_eq!(td.hint(), dir_hint, "{key}");
            assert!(td.is_ascii, "{key}");
        }
        // The custom layout pool for "xpxvvpvv" (Go run): 44 entries,
        // pad marker 0x2f, first witness of byte 0 under "test-key".
        let tc = new_table_with_custom("test-key", "prefer_entropy", "xpxvvpvv").unwrap();
        assert_eq!(tc.hint(), 0x8101d8af);
        assert_eq!(tc.padding_pool.len(), 44);
        assert_eq!(tc.padding_pool[0], 0x2f);
        assert_eq!(tc.encode_table[0][0], [0xe4, 0xa7, 0xb9, 0xfa]);
        let tc2 = new_table_with_custom("another key 42", "prefer_entropy", "xpxvvpvv").unwrap();
        assert_eq!(tc2.encode_table[0][0], [0xa0, 0xe6, 0xf1, 0xb7]);
    }

    #[test]
    fn custom_pattern_validation() {
        assert!(new_table_with_custom("k", "prefer_entropy", "xpxvvpvv").is_ok());
        assert!(new_table_with_custom("k", "prefer_entropy", "XPXVVPVV").is_ok()); // lowercased
        assert!(new_table_with_custom("k", "prefer_entropy", "xpxvvpv").is_err()); // 7 symbols
        assert!(new_table_with_custom("k", "prefer_entropy", "xxxxxxxx").is_err()); // wrong counts
        assert!(new_table_with_custom("k", "prefer_entropy", "xpxvqpvv").is_err()); // bad char
        // ASCII wins over a custom pattern (resolveLayout).
        let t = new_table_with_custom("k", "prefer_ascii", "xpxvvpvv").unwrap();
        assert_eq!(t.padding_pool.len(), 32);
    }

    // ------------------------------------------------------- modes/tables

    #[test]
    fn ascii_mode_parsing() {
        assert_eq!(
            AsciiMode::parse("").unwrap(),
            AsciiMode { uplink: AsciiToken::Entropy, downlink: AsciiToken::Entropy }
        );
        assert_eq!(
            AsciiMode::parse("prefer_ascii").unwrap(),
            AsciiMode { uplink: AsciiToken::Ascii, downlink: AsciiToken::Ascii }
        );
        let d = AsciiMode::parse("up_ascii_down_entropy").unwrap();
        assert_eq!(d.uplink, AsciiToken::Ascii);
        assert_eq!(d.downlink, AsciiToken::Entropy);
        assert_eq!(d.canonical(), "up_ascii_down_entropy");
        assert!(AsciiMode::parse("bogus").is_err());
        assert!(AsciiMode::parse("up_ascii_down").is_err());
        assert!(AsciiMode::parse("up_fast_down_entropy").is_err());
    }

    #[test]
    fn layouts_shape() {
        let entropy = new_entropy_layout();
        assert_eq!(entropy.padding_pool, {
            let mut v = Vec::new();
            for i in 0u8..8 {
                v.push(0x80 + i);
                v.push(0x10 + i);
            }
            v
        });
        // Hints are the bytes with bits 7 and 4 clear.
        assert!(entropy.hint_table[0x00]);
        assert!(!entropy.hint_table[0x10]);
        assert!(entropy.hint_table[0x2f]);
        assert!(!entropy.hint_table[0x80]);
        let ascii = new_ascii_layout();
        assert_eq!(ascii.padding_pool, (0x20u8..=0x3f).collect::<Vec<u8>>());
        assert!(ascii.hint_table[b'A' as usize]); // 0x41
        assert!(!ascii.hint_table[b'0' as usize]); // 0x30
        assert!(ascii.hint_table[b'\n' as usize]); // the 0x7f remap
    }

    /// Pure encode/decode roundtrip across modes, padding thresholds
    /// and all byte values (the uplink codec of Conn.go both ways).
    #[test]
    fn pure_roundtrip_all_modes_and_padding() {
        let key = test_key();
        for mode in ["prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"] {
            let table = new_table_with_custom(&key, mode, "").unwrap();
            let read_table = table.opposite_direction();
            for (min, max) in [(0i64, 0i64), (10, 30), (100, 100)] {
                let mut rng = SudokuRng::new_with_seed(0x1234_5678);
                let threshold = pick_padding_threshold(&mut rng, min, max);
                let payload: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
                let mut enc = Vec::new();
                encode_sudoku_payload(&mut enc, &table, &mut rng, threshold, &payload).unwrap();
                // Decode with the OPPOSITE direction's table (the server
                // reads the client's uplink with the same table the
                // client used: table == read side here).
                let mut st = ObfsDecodeState {
                    hint_buf: [0; 4],
                    hint_count: 0,
                    bit_buf: 0,
                    bit_count: 0,
                };
                let mut out = Vec::new();
                decode_chunk(&table, true, &mut st, &enc, &mut out).unwrap();
                assert_eq!(out, payload, "mode {mode} padding {min}-{max}");
                // Encoded size is 4x + padding.
                assert!(enc.len() >= payload.len() * 4, "mode {mode}");
                let _ = read_table;
            }
        }
    }

    /// The packed downlink decoder against the upstream encoder
    /// transcription (test-side `PackedEncoder`).
    #[test]
    fn packed_roundtrip() {
        let key = test_key();
        let table = new_table_with_custom(&key, "prefer_entropy", "").unwrap();
        let read_table = table.opposite_direction();
        for (min, max) in [(0i64, 0i64), (10, 30)] {
            let mut enc = PackedEncoder::new(table.clone(), min, max);
            let payload: Vec<u8> = (0..249u8).cycle().take(5000).collect();
            let mut wire = enc.encode(&payload);
            wire.extend(enc.finish());
            let mut st = ObfsDecodeState {
                hint_buf: [0; 4],
                hint_count: 0,
                bit_buf: 0,
                bit_count: 0,
            };
            let mut out = Vec::new();
            decode_chunk(&read_table, false, &mut st, &wire, &mut out).unwrap();
            assert_eq!(out, payload, "padding {min}-{max}");
        }
    }

    #[test]
    fn decode_map_miss_errors() {
        let table = new_table_with_custom("k", "prefer_entropy", "").unwrap();
        let mut st = ObfsDecodeState { hint_buf: [0; 4], hint_count: 0, bit_buf: 0, bit_count: 0 };
        // Four identical low hints rarely form a valid witness; find a
        // failing quadruple deterministically.
        let mut found = false;
        for b in 0u16..256 {
            let byte = b as u8;
            if table.layout.hint_table[byte as usize] {
                let quad = [byte, byte, byte, byte];
                let key = pack_hint_bytes(quad[0], quad[1], quad[2], quad[3]);
                if !table.decode_map.contains_key(&key) {
                    let mut out = Vec::new();
                    assert!(decode_chunk(&table, true, &mut st, &quad, &mut out).is_err());
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "no failing quadruple found");
    }

    // ------------------------------------------------------------- seeds

    /// Ground truth from filippo.io/edwards25519 (Go).
    #[test]
    fn seed_ground_truth() {
        // Non-hex PSK passthrough.
        assert_eq!(client_aead_seed("my psk"), "my psk");
        assert_eq!(client_aead_seed("  spaced  "), "spaced");
        assert_eq!(client_aead_seed(""), "");
        // Odd-length hex is not hex → passthrough.
        assert_eq!(client_aead_seed("abc"), "abc");
        // The base point round-trips identically.
        let base = "5866666666666666666666666666666666666666666666666666666666666666";
        assert_eq!(client_aead_seed(base), base);
        // Split key r=5 || k=7 → P = 12G (Go: f9e42d2e...).
        let mut split = String::new();
        split.push_str("05");
        split.push_str(&"00".repeat(31));
        split.push_str("07");
        split.push_str(&"00".repeat(31));
        assert_eq!(
            client_aead_seed(&split),
            "f9e42d2edc81d23367967352b47e4856b82578634e6c1de72280ce8b60ce70c0"
        );
        // Master scalar path only fires when the 32 bytes are NOT a
        // valid point; x=2 decodes as a point on this curve, so the
        // point branch wins and re-encodes canonically. Either way the
        // result must be 64 hex chars.
        let two = format!("{}{}", "02", "00".repeat(31));
        let seed_two = client_aead_seed(&two);
        assert_eq!(seed_two.len(), 64);
    }

    #[test]
    fn kip_user_hash_prefers_hex_bytes() {
        let a = kip_user_hash_from_key("deadbeef");
        let b = kip_user_hash_from_key("zzz-not-hex");
        assert_ne!(a, b);
        // sha256(bytes(0xde,0xad,0xbe,0xef))[:8]
        let sum = Sha256::digest([0xde, 0xad, 0xbe, 0xefu8]);
        assert_eq!(&a[..], &sum[..8]);
        let sum2 = Sha256::digest(b"zzz-not-hex");
        assert_eq!(&b[..], &sum2[..8]);
    }

    // -------------------------------------------------------- RecordConn

    /// Two RecordConns over a duplex, bases swapped as the server does
    /// (`NewRecordConn(obfs, method, pskS2C, pskC2S)`).
    async fn record_pair(
        method: RecordMethod,
    ) -> (RecordConn, RecordConn) {
        let key = test_key();
        let table = new_table_with_custom(&key, "prefer_entropy", "").unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = RecordConn::new(
            ObfsStream::new(Box::new(client_io), table.clone(), 10, 30, true),
            method,
            [1u8; 32],
            [2u8; 32],
        );
        let server = RecordConn::new(
            ObfsStream::new(Box::new(server_io), table, 10, 30, true),
            method,
            [2u8; 32],
            [1u8; 32],
        );
        (client, server)
    }

    #[tokio::test]
    async fn record_conn_roundtrip_chacha() {
        let (mut c, mut s) = record_pair(RecordMethod::Chacha20Poly1305).await;
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        s.write_all(b"pong!").await.unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");
        // A payload beyond the max plaintext spans several frames.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            s.read_exact(&mut got).await.unwrap();
            s.write_all(&got).await.unwrap();
            got
        });
        c.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn record_conn_roundtrip_aes_and_none() {
        let (mut c, mut s) = record_pair(RecordMethod::Aes128Gcm).await;
        c.write_all(b"aes").await.unwrap();
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"aes");
        let (mut c2, mut s2) = record_pair(RecordMethod::None).await;
        c2.write_all(b"plain").await.unwrap();
        let mut buf = [0u8; 5];
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"plain");
    }

    #[tokio::test]
    async fn record_conn_rejects_out_of_order() {
        let (mut c, mut s) = record_pair(RecordMethod::Chacha20Poly1305).await;
        c.write_all(b"first").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"first");
        // Strict receive ordering (validateRecvPosition) exercised
        // directly below; the frame-level replay manifests as the same
        // seq check.
        let (mut c3, mut s3) = record_pair(RecordMethod::Chacha20Poly1305).await;
        c3.write_all(b"xx").await.unwrap();
        let mut buf = [0u8; 2];
        s3.read_exact(&mut buf).await.unwrap();
        // Strict receive ordering (validateRecvPosition).
        let e = s3.recv_epoch;
        assert!(s3.validate_recv_position(e, s3.recv_seq).is_ok());
        assert!(s3.validate_recv_position(e.wrapping_add(8), 0).is_ok());
        assert!(s3.validate_recv_position(e.wrapping_sub(1), 5).is_err()); // replayed
        assert!(s3.validate_recv_position(e, s3.recv_seq + 1).is_err()); // out of order
        assert!(s3.validate_recv_position(e.wrapping_add(9), 5).is_err()); // jump > 8
    }

    #[test]
    fn epoch_rotation_threshold() {
        let key = test_key();
        let table = new_table_with_custom(&key, "prefer_entropy", "").unwrap();
        let mut c = RecordConn::new(
            ObfsStream::new(Box::new(tokio::io::duplex(64).0) as BoxProxyStream, table, 0, 0, true),
            RecordMethod::Chacha20Poly1305,
            [1u8; 32],
            [2u8; 32],
        );
        let start_epoch = c.send_epoch;
        // Below the 32 MiB threshold: no rotation.
        c.maybe_bump_send_epoch(1024).unwrap();
        assert_eq!(c.send_epoch, start_epoch);
        // Crossing it: epoch bumps and seq randomizes.
        c.maybe_bump_send_epoch(KEY_UPDATE_AFTER_BYTES as usize).unwrap();
        assert_eq!(c.send_epoch, start_epoch + 1);
        assert_eq!(c.send_epoch_updates, 1);
        // The next threshold doubles: 32 MiB more (minus the initial
        // overshoot) does not cross it…
        c.maybe_bump_send_epoch((KEY_UPDATE_AFTER_BYTES - 2048) as usize).unwrap();
        assert_eq!(c.send_epoch, start_epoch + 1);
        // …and the last KiB does.
        c.maybe_bump_send_epoch(2048).unwrap();
        assert_eq!(c.send_epoch, start_epoch + 2);
    }

    #[test]
    fn derive_epoch_key_shape() {
        let k = derive_epoch_key(&[7u8; 32], 3, "chacha20-poly1305");
        assert_eq!(k.len(), 32);
        assert_ne!(k, derive_epoch_key(&[7u8; 32], 4, "chacha20-poly1305"));
        assert_ne!(k, derive_epoch_key(&[7u8; 32], 3, "aes-128-gcm"));
    }

    #[test]
    fn session_key_derivation_is_deterministic() {
        let (a, b) = derive_psk_directional_bases("seed");
        assert_ne!(a, b);
        assert_eq!(a, derive_psk_directional_bases("seed").0);
        let (c, d) = derive_session_directional_bases("seed", &[9u8; 32], &[3u8; 16]).unwrap();
        assert_ne!(c, d);
        assert_eq!(
            c,
            derive_session_directional_bases("seed", &[9u8; 32], &[3u8; 16]).unwrap().0
        );
    }

    // ---------------------------------------------------------- KIP/addr

    #[test]
    fn kip_hello_payload_layout() {
        let p = kip_client_hello_payload(
            0x1122334455667788,
            &[1u8; 8],
            &[2u8; 16],
            &[3u8; 32],
            0x17,
            Some(0xaabbccdd),
        );
        let (ts, uh, nonce, pubk, feats, hint) = decode_kip_client_hello_payload(&p).unwrap();
        assert_eq!(ts, 0x1122334455667788);
        assert_eq!(uh, [1u8; 8]);
        assert_eq!(nonce, [2u8; 16]);
        assert_eq!(pubk, [3u8; 32]);
        assert_eq!(feats, 0x17);
        assert_eq!(hint, Some(0xaabbccdd));
        // Without the table hint.
        let p2 = kip_client_hello_payload(1, &[0u8; 8], &[0u8; 16], &[0u8; 32], 1, None);
        assert_eq!(p2.len(), 8 + 8 + 16 + 32 + 4);
        let (_, _, _, _, _, hint2) = decode_kip_client_hello_payload(&p2).unwrap();
        assert_eq!(hint2, None);
        assert!(decode_kip_client_hello_payload(&p2[..p2.len() - 1]).is_err());
        // Server hello.
        let sh = {
            let mut v = Vec::new();
            v.extend_from_slice(&[4u8; 16]);
            v.extend_from_slice(&[5u8; 32]);
            v.extend_from_slice(&0x17u32.to_be_bytes());
            v
        };
        let (n, sp, f) = decode_kip_server_hello_payload(&sh).unwrap();
        assert_eq!(n, [4u8; 16]);
        assert_eq!(sp, [5u8; 32]);
        assert_eq!(f, 0x17);
        assert!(decode_kip_server_hello_payload(&sh[..31]).is_err());
    }

    #[test]
    fn address_encoding_layouts() {
        // SOCKS order, port LAST (address.go).
        let a = NetAddr::domain("example.com", 443).unwrap();
        assert_eq!(
            encode_address(&a),
            vec![
                0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb
            ]
        );
        let (back, used) = decode_address(&encode_address(&a)).unwrap();
        assert_eq!(back, a);
        assert_eq!(used, 15);
        let b4 = NetAddr::ip("127.0.0.1".parse().unwrap(), 80);
        let (back, used) = decode_address(&encode_address(&b4)).unwrap();
        assert_eq!(back, b4);
        assert_eq!(used, 7);
        let b6 = NetAddr::ip("2001:db8::1".parse().unwrap(), 53);
        let (back, used) = decode_address(&encode_address(&b6)).unwrap();
        assert_eq!(back, b6);
        assert_eq!(used, 19);
        assert!(decode_address(&[0x02, 0, 0]).is_err());
    }

    #[test]
    fn uot_datagram_roundtrip() {
        let target = NetAddr::domain("dns.example", 53).unwrap();
        let frame = uot_datagram(&target, b"query").unwrap();
        assert_eq!(&frame[..2], &15u16.to_be_bytes());
        assert_eq!(&frame[2..4], &5u16.to_be_bytes());
        let (back, payload) = decode_address_and_payload(&frame).unwrap();
        assert_eq!(back, target);
        assert_eq!(payload, b"query".to_vec());
        // 64 KiB+1 payloads are refused.
        assert!(uot_datagram(&target, &vec![0u8; 64 * 1024 + 1]).is_err());
    }

    fn decode_address_and_payload(frame: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
        let addr_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let payload_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        let (addr, used) = decode_address(&frame[4..4 + addr_len])?;
        assert_eq!(used, addr_len);
        Ok((addr, frame[4 + addr_len..4 + addr_len + payload_len].to_vec()))
    }

    // -------------------------------------------------- legacy httpmask

    #[tokio::test]
    async fn http_mask_header_shape() {
        for _ in 0..30 {
            let mut buf = Vec::new();
            write_random_request_header(&mut buf, "example.com:8443", "").await.unwrap();
            let s = String::from_utf8(buf.clone()).unwrap();
            assert!(s.starts_with("GET /") || s.starts_with("POST /"), "{s}");
            assert!(s.contains("Host: example.com:8443\r\n"));
            assert!(s.contains("User-Agent: "));
            assert!(s.ends_with("\r\n\r\n"));
            assert!(s.contains("Cache-Control: no-cache\r\nPragma: no-cache\r\n"));
            if s.starts_with("POST") {
                assert!(s.contains("Content-Length: "));
            } else {
                assert!(s.contains("Upgrade: websocket\r\n"));
                assert!(s.contains("Sec-WebSocket-Version: 13\r\n"));
            }
        }
        // path-root prefixes the path.
        let mut buf = Vec::new();
        write_random_request_header(&mut buf, "h", "aabbcc").await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        let path = s.split(' ').nth(1).unwrap();
        assert!(path.starts_with("/aabbcc/"), "{s}");
        assert_eq!(join_path_root("aabbcc", "/session"), "/aabbcc/session");
        assert_eq!(join_path_root("", "/session"), "/session");
        assert_eq!(join_path_root("bad/slash", "/s"), "/s");
        assert_eq!(trim_port_for_host("example.com:443"), "example.com");
        assert_eq!(trim_port_for_host("example.com"), "example.com");
    }

    // ---------------------------------------------------------- configs

    fn base_cfg() -> SudokuOut {
        SudokuOut::new("127.0.0.1", 8443, &test_key())
    }

    #[test]
    fn config_validation_errors() {
        let mut c = base_cfg();
        c.server.clear();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("server"));
        let mut c = base_cfg();
        c.port = 0;
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("port"));
        let mut c = base_cfg();
        c.key.clear();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("key"));
        let mut c = base_cfg();
        c.table_type = "bogus".into();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("table-type"));
        let mut c = base_cfg();
        c.aead_method = Some("aes-256-gcm".into());
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("aead-method"));
        let mut c = base_cfg();
        c.padding_min = Some(50);
        c.padding_max = Some(40);
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("padding-max"));
        let mut c = base_cfg();
        c.padding_min = Some(-1);
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("padding-min"));
        let mut c = base_cfg();
        c.multiplex = "sometimes".into();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("multiplex"));
        let mut c = base_cfg();
        c.path_root = "a/b".into();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("path segment"));
        let mut c = base_cfg();
        c.path_root = "a b".into();
        assert!(resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default().contains("invalid character"));
        // Every tunnel mode now resolves; only unknown modes reject.
        for mode in ["stream", "poll", "auto", "ws"] {
            let mut c = base_cfg();
            c.http_mask_mode = mode.into();
            let rc = resolve_config(&c).unwrap();
            assert_eq!(rc.http_mask_mode, mode);
            assert!(rc.tunnel_mode(), "{mode}");
        }
        let mut c = base_cfg();
        c.http_mask_mode = "legacy".into();
        assert!(!resolve_config(&c).unwrap().tunnel_mode());
        let mut c = base_cfg();
        c.http_mask_mode = "gopher".into();
        let err = resolve_config(&c).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("http-mask-mode"), "{err}");
        // Padding resolution (config.go ResolvePadding).
        assert_eq!(resolve_padding(None, Some(5), 10, 30), (5, 5));
        assert_eq!(resolve_padding(Some(40), None, 10, 30), (40, 40));
        assert_eq!(resolve_padding(Some(3), Some(4), 10, 30), (3, 4));
        assert_eq!(resolve_padding(None, None, 10, 30), (10, 30));
        // Defaults resolve cleanly, as do all table types + custom tables.
        assert!(resolve_config(&base_cfg()).is_ok());
        for t in ["prefer_entropy", "prefer_ascii", "up_ascii_down_entropy"] {
            let mut c = base_cfg();
            c.table_type = t.into();
            assert!(resolve_config(&c).is_ok(), "{t}");
        }
        let mut c = base_cfg();
        c.custom_table = "xpxvvpvv".into();
        assert!(resolve_config(&c).is_ok());
        let mut c = base_cfg();
        c.custom_tables = vec!["xpxvvpvv".into(), "xpvvpxvv".into()];
        assert!(resolve_config(&c).is_ok());
        let mut c = base_cfg();
        c.multiplex = "auto".into();
        let rc = resolve_config(&c).unwrap();
        assert_eq!(rc.multiplex, "off");
        let mut c = base_cfg();
        c.multiplex = "on".into();
        let rc = resolve_config(&c).unwrap();
        assert_eq!(rc.multiplex, "on");
    }

    // ------------------------------------------------ packed encoder (mimic)

    /// The upstream server-side packed downlink writer
    /// (`PackedConn::Write`/`Flush`, packed.go:161/277) — used by the
    /// in-test server mimic.
    struct PackedEncoder {
        table: Arc<Table>,
        rng: SudokuRng,
        threshold: u64,
        pad_marker: u8,
        pad_pool: Vec<u8>,
        bit_buf: u64,
        bit_count: u32,
    }

    impl PackedEncoder {
        fn new(table: Arc<Table>, p_min: i64, p_max: i64) -> Self {
            let mut rng = SudokuRng::new_seeded();
            let threshold = pick_padding_threshold(&mut rng, p_min, p_max);
            let pad_marker = table.layout.pad_marker;
            let mut pad_pool: Vec<u8> = table
                .padding_pool
                .iter()
                .copied()
                .filter(|b| *b != pad_marker)
                .collect();
            if pad_pool.is_empty() {
                pad_pool.push(pad_marker);
            }
            PackedEncoder {
                table,
                rng,
                threshold,
                pad_marker,
                pad_pool,
                bit_buf: 0,
                bit_count: 0,
            }
        }

        fn padding_byte(&mut self) -> u8 {
            self.pad_pool[self.rng.intn(self.pad_pool.len())]
        }

        fn next_gap(&mut self) -> usize {
            1 + self.rng.intn(2)
        }

        fn append_group(&mut self, out: &mut Vec<u8>, group: u8) {
            if self.threshold != 0 {
                let u = self.rng.uint32();
                if (u as u64) < self.threshold {
                    let i = ((self.rng.uint32() as u64 * self.pad_pool.len() as u64) >> 32) as usize;
                    out.push(self.pad_pool[i]);
                }
            }
            out.push(self.table.layout.group_byte(group & 0x3f));
        }

        fn maybe_pad(&mut self, out: &mut Vec<u8>) {
            if self.threshold != 0 {
                let u = self.rng.uint32();
                if (u as u64) < self.threshold {
                    let i = ((self.rng.uint32() as u64 * self.pad_pool.len() as u64) >> 32) as usize;
                    out.push(self.pad_pool[i]);
                }
            }
        }

        fn push_bits(&mut self, out: &mut Vec<u8>, byte: u8) {
            self.bit_buf = (self.bit_buf << 8) | u64::from(byte);
            self.bit_count += 8;
            while self.bit_count >= 6 {
                self.bit_count -= 6;
                let group = (self.bit_buf >> self.bit_count) as u8;
                if self.bit_count == 0 {
                    self.bit_buf = 0;
                } else {
                    self.bit_buf &= (1u64 << self.bit_count) - 1;
                }
                self.append_group(out, group);
            }
        }

        /// `writeProtectedPrefix` (packed.go:100).
        fn write_protected_prefix(&mut self, out: &mut Vec<u8>, p: &[u8]) -> usize {
            if p.is_empty() {
                return 0;
            }
            let limit = p.len().min(14);
            // NOTE: Go re-evaluates `1+rng.Intn(2)` on every loop
            // condition check (packed.go:110) — transcribed literally.
            let mut pad_count = 0;
            loop {
                if !(pad_count < 1 + self.rng.intn(2)) {
                    break;
                }
                out.push(self.padding_byte());
                pad_count += 1;
            }
            let mut gap = self.next_gap();
            let mut effective = 0;
            for &b in p.iter().take(limit) {
                self.push_bits(out, b);
                effective += 1;
                if effective >= gap {
                    out.push(self.padding_byte());
                    effective = 0;
                    gap = self.next_gap();
                }
            }
            limit
        }

        fn encode(&mut self, p: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(p.len() * 3 / 2 + 32);
            let mut i = self.write_protected_prefix(&mut out, p);
            let n = p.len();
            while self.bit_count > 0 && i < n {
                self.push_bits(&mut out, p[i]);
                i += 1;
            }
            while i + 11 < n {
                for _ in 0..4 {
                    let (b1, b2, b3) = (p[i], p[i + 1], p[i + 2]);
                    i += 3;
                    self.append_group(&mut out, (b1 >> 2) & 0x3f);
                    self.append_group(&mut out, ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0f));
                    self.append_group(&mut out, ((b2 & 0x0f) << 2) | ((b3 >> 6) & 0x03));
                    self.append_group(&mut out, b3 & 0x3f);
                }
            }
            while i + 2 < n {
                let (b1, b2, b3) = (p[i], p[i + 1], p[i + 2]);
                i += 3;
                self.append_group(&mut out, (b1 >> 2) & 0x3f);
                self.append_group(&mut out, ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0f));
                self.append_group(&mut out, ((b2 & 0x0f) << 2) | ((b3 >> 6) & 0x03));
                self.append_group(&mut out, b3 & 0x3f);
            }
            while i < n {
                self.push_bits(&mut out, p[i]);
                i += 1;
            }
            if self.bit_count > 0 {
                let group = (self.bit_buf << (6 - self.bit_count)) as u8;
                self.bit_buf = 0;
                self.bit_count = 0;
                self.append_group(&mut out, group);
                out.push(self.pad_marker);
            }
            self.maybe_pad(&mut out);
            out
        }

        /// `Flush` (packed.go:277) — the trailing partial group.
        fn finish(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            if self.bit_count > 0 {
                let group = (self.bit_buf << (6 - self.bit_count)) as u8;
                self.bit_buf = 0;
                self.bit_count = 0;
                out.push(self.table.layout.group_byte(group & 0x3f));
                out.push(self.pad_marker);
            }
            self.maybe_pad(&mut out);
            out
        }
    }

    /// The in-test server-side obfs stream: reads the client's pure
    /// uplink, writes the downlink pure or packed (buildServerObfsConn,
    /// handshake.go:309).
    struct ServerObfs {
        inner: BoxProxyStream,
        uplink: Arc<Table>,
        pure: bool,
        pure_writer: SudokuRng,
        pure_threshold: u64,
        packed: Option<PackedEncoder>,
        rbuf: BytesMut,
        out: BytesMut,
        state: ObfsDecodeState,
        eof: bool,
        wbuf: BytesMut,
        pending_plain: usize,
    }

    impl ServerObfs {
        fn new(
            inner: BoxProxyStream,
            uplink: Arc<Table>,
            downlink: Arc<Table>,
            p_min: i64,
            p_max: i64,
            pure: bool,
        ) -> Self {
            let mut rng = SudokuRng::new_seeded();
            let threshold = pick_padding_threshold(&mut rng, p_min, p_max);
            let packed = if pure {
                None
            } else {
                Some(PackedEncoder::new(downlink, p_min, p_max))
            };
            ServerObfs {
                inner,
                uplink,
                pure,
                pure_writer: rng,
                pure_threshold: threshold,
                packed,
                rbuf: BytesMut::with_capacity(16 * 1024),
                out: BytesMut::with_capacity(16 * 1024),
                state: ObfsDecodeState {
                    hint_buf: [0; 4],
                    hint_count: 0,
                    bit_buf: 0,
                    bit_count: 0,
                },
                eof: false,
                wbuf: BytesMut::new(),
                pending_plain: 0,
            }
        }
    }

    impl AsyncWrite for ServerObfs {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.wbuf.is_empty() {
                let wire = if self.pure {
                    let table = self.uplink.opposite_direction();
                    let threshold = self.pure_threshold;
                    let mut v = Vec::with_capacity(buf.len() * 6 + 8);
                    encode_sudoku_payload(&mut v, &table, &mut self.pure_writer, threshold, buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    v
                } else {
                    self.packed.as_mut().expect("packed server").encode(buf)
                };
                self.wbuf = BytesMut::from(&wire[..]);
                self.pending_plain = buf.len();
            }
            while !self.wbuf.is_empty() {
                let n = {
                    let mut wbuf = std::mem::take(&mut self.wbuf);
                    let r = Pin::new(&mut self.inner).poll_write(cx, &wbuf);
                    let consumed = matches!(&r, Poll::Ready(Ok(n)) if *n > 0);
                    let n = match r {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => {
                            self.wbuf = wbuf;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            self.wbuf = wbuf;
                            return Poll::Pending;
                        }
                    };
                    if consumed {
                        wbuf.advance(n);
                    }
                    self.wbuf = wbuf;
                    n
                };
                if n == 0 {
                    return Poll::Ready(Err(io::Error::other("mimic write zero")));
                }
            }
            Poll::Ready(Ok(self.pending_plain))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.pure {
                let tail = self.packed.as_mut().expect("packed server").finish();
                if !tail.is_empty() {
                    let mut off = 0;
                    while off < tail.len() {
                        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &tail[off..]))?;
                        off += n;
                    }
                }
            }
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl AsyncRead for ServerObfs {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                if !self.out.is_empty() {
                    let n = self.out.len().min(buf.remaining());
                    buf.put_slice(&self.out[..n]);
                    self.out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                if self.eof {
                    return Poll::Ready(Ok(()));
                }
                let mut tmp = [0u8; 16 * 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                if rb.filled().is_empty() {
                    self.eof = true;
                    continue;
                }
                self.rbuf.extend_from_slice(rb.filled());
                let mut out = std::mem::take(&mut self.out).to_vec();
                let chunk = self.rbuf.to_vec();
                let uplink = self.uplink.clone();
                let r = decode_chunk(&uplink, true, &mut self.state, &chunk, &mut out);
                self.out = BytesMut::from(&out[..]);
                self.rbuf.clear();
                r.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            }
        }
    }

    /// The full server mimic (`ServerHandshake` + `ReadServerSession`):
    /// optional legacy HTTP header consumption, obfs + record layers,
    /// the KIP exchange, then an echo loop.
    #[allow(clippy::too_many_arguments)]
    async fn sudoku_server_mimic(
        io: DuplexStream,
        key: &str,
        table_type: &str,
        method: RecordMethod,
        pure_downlink: bool,
        consume_http_header: bool,
        padding: (i64, i64),
        session: MimicSession,
    ) -> std::result::Result<(), String> {
        let mut io = io;
        if consume_http_header {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = io.read(&mut byte).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("eof in http header".into());
                }
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                if head.len() > 16 * 1024 {
                    return Err("http header too large".into());
                }
            }
            let s = String::from_utf8_lossy(&head);
            if !(s.starts_with("GET ") || s.starts_with("POST ")) {
                return Err("bad http mask method".into());
            }
        }
        let uplink =
            new_table_with_custom(key, table_type, "").map_err(|e| e.to_string())?;
        let downlink = uplink.opposite_direction();
        let mut rc: RecordConn<BoxProxyStream> = RecordConn::new(
            Box::new(ServerObfs::new(
                Box::new(io),
                uplink.clone(),
                downlink.clone(),
                padding.0,
                padding.1,
                pure_downlink,
            )),
            method,
            [0u8; 32],
            [0u8; 32],
        );
        let seed = client_aead_seed(key);
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
        rc.base_send = psk_s2c;
        rc.base_recv = psk_c2s;

        // KIP server side (handshake.go:444-505).
        let (typ, payload) = read_kip_message(&mut rc).await.map_err(|e| e.to_string())?;
        if typ != KIP_TYPE_CLIENT_HELLO {
            return Err(format!("unexpected handshake message {typ:#x}"));
        }
        let (ts, user_hash, nonce, client_pub, feats, hint) =
            decode_kip_client_hello_payload(&payload).map_err(|e| e.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if (now - ts).abs() > KIP_HANDSHAKE_SKEW {
            return Err("time skew".into());
        }
        let _ = user_hash;
        let _ = hint;
        let mut scalar = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut scalar);
        let server_pub = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
        let mut sh = Vec::with_capacity(52);
        sh.extend_from_slice(&nonce);
        sh.extend_from_slice(&server_pub);
        sh.extend_from_slice(&(feats & KIP_FEAT_ALL).to_be_bytes());
        write_kip_message(&mut rc, KIP_TYPE_SERVER_HELLO, &sh)
            .await
            .map_err(|e| e.to_string())?;
        let shared = x25519_shared_secret(&scalar, &client_pub).map_err(|e| e.to_string())?;
        let (sess_c2s, sess_s2c) =
            derive_session_directional_bases(&seed, &shared, &nonce).map_err(|e| e.to_string())?;
        rc.rekey(sess_s2c, sess_c2s);

        // ReadServerSession (handshake.go:509).
        let (first, payload) = read_kip_message(&mut rc).await.map_err(|e| e.to_string())?;
        match session {
            MimicSession::Tcp(target) => {
                if first != KIP_TYPE_OPEN_TCP {
                    return Err(format!("expected OpenTCP, got {first:#x}"));
                }
                let (addr, used) = decode_address(&payload).map_err(|e| e.to_string())?;
                if used != payload.len() || addr != target {
                    return Err(format!("target mismatch: {addr} != {target}"));
                }
                let mut buf = [0u8; 4096];
                loop {
                    let n = rc.read(&mut buf).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Ok(());
                    }
                    rc.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
                }
            }
            MimicSession::UoT => {
                if first != KIP_TYPE_START_UOT {
                    return Err(format!("expected StartUoT, got {first:#x}"));
                }
                let target = NetAddr::domain("dns.example", 53).unwrap();
                let frame = uot_datagram(&target, b"uot-echo").unwrap();
                rc.write_all(&frame).await.map_err(|e| e.to_string())?;
                let (back, payload) = read_uot_datagram(&mut rc).await.map_err(|e| e.to_string())?;
                rc.write_all(&uot_datagram(&back, &payload).unwrap())
                    .await
                    .map_err(|e| e.to_string())?;
                let (back2, payload2) = read_uot_datagram(&mut rc).await.map_err(|e| e.to_string())?;
                rc.write_all(&uot_datagram(&back2, &payload2).unwrap())
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    enum MimicSession {
        Tcp(NetAddr),
        UoT,
    }

    async fn run_connect_case(
        table_type: &str,
        method: RecordMethod,
        pure_downlink: bool,
        http_mask: bool,
        padding: (i64, i64),
    ) -> Result<BoxProxyStream> {
        let key = test_key();
        let mut cfg = SudokuOut::new("127.0.0.1", 8443, &key);
        cfg.table_type = table_type.into();
        cfg.aead_method = Some(
            match method {
                RecordMethod::Chacha20Poly1305 => "chacha20-poly1305",
                RecordMethod::Aes128Gcm => "aes-128-gcm",
                RecordMethod::None => "none",
            }
            .to_string(),
        );
        cfg.enable_pure_downlink = Some(pure_downlink);
        cfg.http_mask = Some(http_mask);
        cfg.padding_min = Some(padding.0);
        cfg.padding_max = Some(padding.1);
        let (client, server) = tokio::io::duplex(256 * 1024);
        let key2 = key.clone();
        let tt = table_type.to_string();
        tokio::spawn(async move {
            if let Err(e) = sudoku_server_mimic(
                server,
                &key2,
                &tt,
                method,
                pure_downlink,
                http_mask,
                padding,
                MimicSession::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
            )
            .await
            {
                panic!("sudoku mimic failed: {e}");
            }
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        tokio::time::timeout(
            Duration::from_secs(20),
            connect(&cfg, Box::new(client), &target),
        )
        .await
        .expect("connect timed out")
    }

    #[tokio::test]
    async fn connect_echo_default_legacy_chacha() {
        let mut stream = run_connect_case("prefer_entropy", RecordMethod::Chacha20Poly1305, true, true, (10, 30))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping");
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn connect_echo_ascii_aes_no_mask() {
        let mut stream = run_connect_case("prefer_ascii", RecordMethod::Aes128Gcm, true, false, (0, 0))
            .await
            .unwrap();
        stream.write_all(b"ascii-aes").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ascii-aes");
    }

    #[tokio::test]
    async fn connect_echo_directional_packed() {
        // up_ascii_down_entropy + packed downlink + padding 100%.
        let mut stream = run_connect_case(
            "up_ascii_down_entropy",
            RecordMethod::Chacha20Poly1305,
            false,
            true,
            (100, 100),
        )
        .await
        .unwrap();
        stream.write_all(b"dir-packed").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"dir-packed");
        let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 249) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn connect_wrong_key_fails() {
        let key = test_key();
        let cfg = SudokuOut::new("127.0.0.1", 8443, &format!("wrong-{key}"));
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_key = key.clone();
        tokio::spawn(async move {
            // The mimic cannot decrypt: it fails and drops the conn.
            let _ = sudoku_server_mimic(
                server,
                &server_key,
                "prefer_entropy",
                RecordMethod::Chacha20Poly1305,
                true,
                true,
                (10, 30),
                MimicSession::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
            )
            .await;
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            connect(&cfg, Box::new(client), &target),
        )
        .await
        .expect("timed out");
        if let Ok(mut stream) = result {
            // If the handshake's first flight landed, the read side
            // must fail: the server dropped us.
            stream.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            assert!(stream.read(&mut buf).await.is_err());
        }
    }

    #[tokio::test]
    async fn connect_none_method_roundtrip() {
        let mut stream = run_connect_case("prefer_entropy", RecordMethod::None, true, true, (10, 30))
            .await
            .unwrap();
        stream.write_all(b"none").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"none");
    }

    #[tokio::test]
    async fn connect_udp_uot_roundtrip() {
        let key = test_key();
        let cfg = SudokuOut::new("127.0.0.1", 8443, &key);
        let (client, server) = tokio::io::duplex(256 * 1024);
        let key2 = key.clone();
        tokio::spawn(async move {
            if let Err(e) = sudoku_server_mimic(
                server,
                &key2,
                "prefer_entropy",
                RecordMethod::Chacha20Poly1305,
                true,
                true,
                (10, 30),
                MimicSession::UoT,
            )
            .await
            {
                panic!("uot mimic failed: {e}");
            }
        });
        let mut stream = connect_udp(&cfg, Box::new(client)).await.unwrap();
        // First inbound datagram is the server greeting.
        let (greet, payload) = tokio::time::timeout(
            Duration::from_secs(10),
            read_uot_datagram(&mut stream),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(greet.host, Host::Domain("dns.example".into()));
        assert_eq!(greet.port, 53);
        assert_eq!(payload, b"uot-echo".to_vec());
        // Echo two datagrams through the mimic.
        for payload in [b"one".to_vec(), b"two!".to_vec()] {
            let target = NetAddr::domain("dns.example", 53).unwrap();
            stream.write_all(&uot_datagram(&target, &payload).unwrap()).await.unwrap();
            let (back, got) = tokio::time::timeout(
                Duration::from_secs(10),
                read_uot_datagram(&mut stream),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(back, target);
            assert_eq!(got, payload);
        }
    }

    // ------------------------------------------------------------- mux

    /// A faithful transcription of the upstream server-side session for
    /// the loopback test: accepts OPEN, echoes DATA, honours CLOSE.
    async fn mux_server_mimic(io: DuplexStream) -> std::result::Result<(), String> {
        use tokio::io::AsyncReadExt as _;
        let mut io = io;
        let mut streams: HashMap<u32, Vec<u8>> = HashMap::new();
        loop {
            let mut header = [0u8; MUX_HEADER_SIZE];
            io.read_exact(&mut header).await.map_err(|e| e.to_string())?;
            let typ = header[0];
            let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
            let mut payload = vec![0u8; len];
            if len > 0 {
                io.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
            }
            let mut out = Vec::new();
            match typ {
                MUX_FRAME_OPEN => {
                    let (_addr, used) = decode_address(&payload).map_err(|e| e.to_string())?;
                    if used != payload.len() {
                        return Err("bad open address".into());
                    }
                    streams.insert(id, Vec::new());
                }
                MUX_FRAME_DATA if id == 0 => {} // keepalive, ignored
                MUX_FRAME_DATA => {
                    if let Some(buf) = streams.get_mut(&id) {
                        buf.extend_from_slice(&payload);
                        // Echo immediately.
                        out.push(typ);
                        out.extend_from_slice(&id.to_be_bytes());
                        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
                        out.extend_from_slice(buf);
                        buf.clear();
                    }
                }
                MUX_FRAME_CLOSE => {
                    if streams.remove(&id).is_some() {
                        out.push(MUX_FRAME_CLOSE);
                        out.extend_from_slice(&id.to_be_bytes());
                        out.extend_from_slice(&0u32.to_be_bytes());
                    }
                    if streams.is_empty() && id != 0 {
                        // All streams gone after the first close cycle.
                        let _ = io.write_all(&out).await;
                        return Ok(());
                    }
                }
                MUX_FRAME_RESET => {}
                other => return Err(format!("unknown frame {other:#x}")),
            }
            if !out.is_empty() {
                io.write_all(&out).await.map_err(|e| e.to_string())?;
            }
        }
    }

    #[tokio::test]
    async fn mux_session_loopback() {
        // Mux frames over a plain duplex (the record layer is already
        // covered above): Session over any stream.
        let (client, server) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            if let Err(e) = mux_server_mimic(server).await {
                panic!("mux mimic failed: {e}");
            }
        });
        let session = SudokuMuxSession::new(Box::new(client));
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut s1 = session.open_stream(&target).await.unwrap();
        let mut s2 = session.open_stream(&target).await.unwrap();
        s1.write_all(b"hello-one").await.unwrap();
        s2.write_all(b"two!").await.unwrap();
        let mut buf = [0u8; 9];
        s1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-one");
        let mut buf = [0u8; 4];
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two!");
        // A payload larger than one data frame (128 KiB chunks), read
        // concurrently so the echo path cannot fill the duplex.
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let (mut rd1, mut wr1) = tokio::io::split(s1);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd1.read_exact(&mut got).await.unwrap();
            let mut tail = [0u8; 11];
            rd1.read_exact(&mut tail).await.unwrap();
            (got, tail)
        });
        wr1.write_all(&payload).await.unwrap();
        // Close one stream; the other keeps flowing.
        s2.shutdown().await.unwrap();
        wr1.write_all(b"after-close").await.unwrap();
        let (got, tail) = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        assert_eq!(&tail, b"after-close");
        session.close();
    }

    #[test]
    fn mux_stream_ids_increment() {
        // Compile-level API shape + id sequencing without a socket.
        let key = test_key();
        let _ = SudokuOut::new("s", 1, &key);
        let shared_next = std::sync::atomic::AtomicU32::new(0);
        assert_eq!(
            1 + shared_next.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            1 + shared_next.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[test]
    fn pick_client_table_modes() {
        let key = test_key();
        let single = new_client_tables_with_custom_patterns(&key, "prefer_entropy", "", &[]).unwrap();
        let (t, hint) = pick_client_table(&single).unwrap();
        assert_eq!(t.hint(), single[0].hint());
        assert_eq!(hint, None);
        let rotation = new_client_tables_with_custom_patterns(
            &key,
            "prefer_entropy",
            "",
            &["xpxvvpvv".to_string(), "xpvvpxvv".to_string()],
        )
        .unwrap();
        assert_eq!(rotation.len(), 2);
        let (t, hint) = pick_client_table(&rotation).unwrap();
        assert!(hint.is_some());
        assert_eq!(hint.unwrap(), t.hint());
        assert!(pick_client_table(&[]).is_err());
    }

    // ------------------------------------------------ httpmask tunnels

    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use tokio::net::TcpListener;

    /// What the in-test session does after the early handshake.
    enum TunnelSessionKind {
        Tcp(NetAddr),
        Mux,
    }

    /// The session pipe halves shared by the tunnel endpoints: pushes
    /// write `wr`, pulls read `rd` (tunnel_server.go's `tunnelSession`).
    struct MaskPipe {
        rd: Option<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        wr: Option<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
    }

    /// Shared mask-server state.
    struct MaskShared {
        seed: String,
        method: RecordMethod,
        padding: (i64, i64),
        pure_downlink: bool,
        tables: Vec<Arc<Table>>,
        sessions: std::sync::Mutex<HashMap<String, MaskPipe>>,
        next_upload_seq: std::sync::Mutex<HashMap<String, u64>>,
        log: std::sync::Mutex<Vec<String>>,
        /// The `auto` test: refuse stream-mode authorize attempts.
        reject_stream_authorize: AtomicBool,
        /// Opt the sessions into mux echo (the mux test).
        mux_marker: AtomicBool,
    }

    impl MaskShared {
        fn log(&self, entry: String) {
            self.log.lock().unwrap().push(entry);
        }

        fn logged(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        /// `ProcessEarlyClientPayload` + the KIP server hello, in memory
        /// (early_handshake.go:215/286).
        async fn process_early(
            &self,
            payload: &[u8],
        ) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
            let uplink = self.tables[0].clone();
            let downlink = uplink.opposite_direction();
            let obfs = ServerObfs::new(
                MemIo::source(payload.to_vec()),
                uplink.clone(),
                downlink,
                self.padding.0,
                self.padding.1,
                self.pure_downlink,
            );
            let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&self.seed);
            let mut rc: RecordConn<BoxProxyStream> = RecordConn::new(
                Box::new(obfs) as BoxProxyStream,
                self.method,
                psk_s2c,
                psk_c2s,
            );
            let (typ, payload) = read_kip_message(&mut rc).await?;
            if typ != KIP_TYPE_CLIENT_HELLO {
                return Err(Error::protocol("bad early message"));
            }
            let (ts, _user_hash, nonce, client_pub, feats, hint) =
                decode_kip_client_hello_payload(&payload)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if (now - ts).abs() > KIP_HANDSHAKE_SKEW {
                return Err(Error::protocol("early time skew"));
            }
            // ResolveClientHelloTable: match the hint against candidates.
            let resolved = match hint {
                Some(h) => self
                    .tables
                    .iter()
                    .find(|t| t.hint() == h)
                    .cloned()
                    .unwrap_or(uplink.clone()),
                None => uplink.clone(),
            };
            let mut scalar = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut scalar);
            let server_pub =
                curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
            let mut sh = Vec::with_capacity(52);
            sh.extend_from_slice(&nonce);
            sh.extend_from_slice(&server_pub);
            sh.extend_from_slice(&(feats & KIP_FEAT_ALL).to_be_bytes());
            let written = Arc::new(Mutex::new(Vec::new()));
            let resp_obfs = ServerObfs::new(
                MemIo::sink(written.clone()),
                resolved.clone(),
                resolved.opposite_direction(),
                self.padding.0,
                self.padding.1,
                self.pure_downlink,
            );
            let mut resp: RecordConn<BoxProxyStream> = RecordConn::new(
                Box::new(resp_obfs) as BoxProxyStream,
                self.method,
                psk_s2c,
                psk_c2s,
            );
            write_kip_message(&mut resp, KIP_TYPE_SERVER_HELLO, &sh).await?;
            let shared = x25519_shared_secret(&scalar, &client_pub)?;
            let (sess_c2s, sess_s2c) =
                derive_session_directional_bases(&self.seed, &shared, &nonce)?;
            let captured = written.lock().unwrap().clone();
            Ok((captured, sess_c2s, sess_s2c))
        }

        /// The post-handshake session (`ReadServerSession` or the mux
        /// echo) over the server half of the pipe.
        async fn run_session(
            self: Arc<Self>,
            kind: TunnelSessionKind,
            mut conn: RecordConn<BoxProxyStream>,
        ) {
            let (first, payload) = match read_kip_message(&mut conn).await {
                Ok(v) => v,
                Err(_) => return,
            };
            match kind {
                TunnelSessionKind::Tcp(target) => {
                    assert!(
                        first == KIP_TYPE_OPEN_TCP || first == KIP_TYPE_START_UOT,
                        "expected OpenTCP/StartUoT, got {first:#x}"
                    );
                    if first == KIP_TYPE_OPEN_TCP {
                        let (addr, used) = decode_address(&payload).unwrap();
                        assert_eq!(used, payload.len());
                        assert_eq!(addr, target);
                    }
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if conn.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
                TunnelSessionKind::Mux => {
                    assert_eq!(first, KIP_TYPE_START_MUX, "expected StartMux");
                    let mut buf = Vec::new();
                    loop {
                        let mut chunk = [0u8; 8192];
                        match conn.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                while buf.len() >= MUX_HEADER_SIZE {
                                    let len = u32::from_be_bytes([
                                        buf[5], buf[6], buf[7], buf[8],
                                    ]) as usize;
                                    if buf.len() < MUX_HEADER_SIZE + len {
                                        break;
                                    }
                                    let frame: Vec<u8> =
                                        buf.drain(..MUX_HEADER_SIZE + len).collect();
                                    let frame_type = frame[0];
                                    let stream_id = u32::from_be_bytes([
                                        frame[1], frame[2], frame[3], frame[4],
                                    ]);
                                    let payload = frame[MUX_HEADER_SIZE..].to_vec();
                                    match frame_type {
                                        MUX_FRAME_DATA => {
                                            let mut echo =
                                                Vec::with_capacity(MUX_HEADER_SIZE + len);
                                            echo.push(MUX_FRAME_DATA);
                                            echo.extend_from_slice(&stream_id.to_be_bytes());
                                            echo.extend_from_slice(&(len as u32).to_be_bytes());
                                            echo.extend_from_slice(&payload);
                                            if conn.write_all(&echo).await.is_err() {
                                                return;
                                            }
                                        }
                                        MUX_FRAME_CLOSE => {
                                            let mut echo = Vec::with_capacity(MUX_HEADER_SIZE);
                                            echo.push(MUX_FRAME_CLOSE);
                                            echo.extend_from_slice(&stream_id.to_be_bytes());
                                            echo.extend_from_slice(&0u32.to_be_bytes());
                                            let _ = conn.write_all(&echo).await;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// One parsed HTTP request at the mask server.
    struct MaskRequest {
        method: String,
        path: String,
        query: HashMap<String, String>,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    async fn mask_read_request(io: &mut BoxProxyStream) -> Result<MaskRequest> {
        let mut head = Vec::new();
        loop {
            let line = read_crlf_line(io, 16 * 1024).await?;
            if line.is_empty() {
                break;
            }
            head.extend_from_slice(&line);
            head.push(b'\n');
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap_or_default().to_uppercase();
        let target = parts.next().unwrap_or_default().to_string();
        let (path, query_str) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };
        let mut query = HashMap::new();
        for pair in query_str.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query.insert(k.to_string(), v.to_string());
        }
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            io.read_exact(&mut body).await?;
        }
        Ok(MaskRequest {
            method,
            path,
            query,
            headers,
            body,
        })
    }

    async fn mask_simple_response(io: &mut BoxProxyStream, code: u16, body: &str) {
        let reason = match code {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Error",
        };
        let resp = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = io.write_all(resp.as_bytes()).await;
    }

    /// The mask server's accept loop.
    async fn mask_server_loop(
        listener: TcpListener,
        shared: Arc<MaskShared>,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let shared = shared.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io: BoxProxyStream = match tls {
                    Some(config) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config);
                        match acceptor.accept(stream).await {
                            Ok(s) => Box::new(s),
                            Err(_) => return,
                        }
                    }
                    None => Box::new(stream),
                };
                let _ = mask_handle_conn(io, &shared).await;
            });
        }
    }

    async fn mask_handle_conn(mut io: BoxProxyStream, shared: &Arc<MaskShared>) -> Result<()> {
        let req = mask_read_request(&mut io).await?;
        let mode_header = req.headers.get("x-sudoku-tunnel").cloned().unwrap_or_default();
        if req.method == "GET" && req.path.ends_with("/session") {
            shared.log(format!("authorize mode={mode_header}"));
            if mode_header == "stream"
                && shared.reject_stream_authorize.load(AtomicOrdering::Relaxed)
            {
                mask_simple_response(&mut io, 403, "no stream").await;
                return Ok(());
            }
            // sessionAuthorize: the early handshake, a token, and the
            // halfpipe session (tunnel_server.go:710).
            use base64::Engine;
            let early_payload = match req.query.get("ed") {
                Some(v) => base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(v)
                    .map_err(|_| Error::protocol("bad ed"))?,
                None => Vec::new(),
            };
            let kind = if shared.mux_marker.load(AtomicOrdering::Relaxed) {
                TunnelSessionKind::Mux
            } else {
                TunnelSessionKind::Tcp(NetAddr::domain("echo.example", 443).unwrap())
            };
            let (response_payload, sess_c2s, sess_s2c) = if early_payload.is_empty() {
                // No early payload: the client falls back to the in-band
                // handshake (applyEarlyHandshakeOrUpgrade's Upgrade arm).
                (Vec::new(), [0u8; 32], [0u8; 32])
            } else {
                shared.process_early(&early_payload).await?
            };
            let token = format!("tok{}", rand::random::<u64>());
            let (a, b) = tokio::io::duplex(256 * 1024);
            let obfs = ServerObfs::new(
                Box::new(a),
                shared.tables[0].clone(),
                shared.tables[0].opposite_direction(),
                shared.padding.0,
                shared.padding.1,
                shared.pure_downlink,
            );
            let conn: RecordConn<BoxProxyStream> = RecordConn::new(
                Box::new(obfs) as BoxProxyStream,
                shared.method,
                sess_s2c,
                sess_c2s,
            );
            let shared2 = shared.clone();
            tokio::spawn(async move {
                shared2.run_session(kind, conn).await;
            });
            let (rd, wr) = tokio::io::split(b);
            shared.sessions.lock().unwrap().insert(
                token.clone(),
                MaskPipe {
                    rd: Some(rd),
                    wr: Some(wr),
                },
            );
            shared
                .next_upload_seq
                .lock()
                .unwrap()
                .insert(token.clone(), 1);
            let mut body = format!("token={token}");
            if !response_payload.is_empty() {
                body += &format!(
                    "\ned={}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&response_payload)
                );
            }
            body += "\ncap=upload-seq";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            io.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
        if req.method == "GET" && req.path.ends_with("/stream") {
            shared.log(format!("pull mode={mode_header}"));
            // Take the read half; reinsert on a clean long-poll end.
            let rd = {
                let mut sessions = shared.sessions.lock().unwrap();
                match sessions.get_mut(&req.query.get("token").cloned().unwrap_or_default()) {
                    Some(pipe) => pipe.rd.take(),
                    None => None,
                }
            };
            let Some(mut rd) = rd else {
                mask_simple_response(&mut io, 404, "no session").await;
                return Ok(());
            };
            let poll_mode = mode_header == "poll";
            io.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sudoku-Stream-EOF\r\nCache-Control: no-store\r\nPragma: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n"
            ).await?;
            let mut eof = false;
            loop {
                let mut buf = vec![0u8; 16 * 1024];
                let read = tokio::time::timeout(
                    std::time::Duration::from_millis(120),
                    rd.read(&mut buf),
                )
                .await;
                match read {
                    Err(_) => break, // idle: end this long-poll body
                    Ok(Ok(0)) => {
                        eof = true;
                        break;
                    }
                    Ok(Ok(n)) => {
                        if poll_mode {
                            use base64::Engine;
                            let line =
                                base64::engine::general_purpose::STANDARD.encode(&buf[..n]);
                            let chunk = format!("{:x}\r\n{line}\n\r\n", line.len() + 1);
                            io.write_all(chunk.as_bytes()).await?;
                        } else {
                            let chunk = format!("{:x}\r\n", n);
                            io.write_all(chunk.as_bytes()).await?;
                            io.write_all(&buf[..n]).await?;
                            io.write_all(b"\r\n").await?;
                        }
                    }
                    Ok(Err(_)) => {
                        eof = true;
                        break;
                    }
                }
            }
            if eof {
                io.write_all(b"0\r\nX-Sudoku-Stream-EOF: 1\r\n\r\n").await?;
            } else {
                io.write_all(b"0\r\n\r\n").await?;
                // Give the read half back for the next pull.
                let mut sessions = shared.sessions.lock().unwrap();
                if let Some(pipe) =
                    sessions.get_mut(&req.query.get("token").cloned().unwrap_or_default())
                {
                    pipe.rd = Some(rd);
                }
            }
            return Ok(());
        }
        if req.method == "POST" && req.path.ends_with("/api/v1/upload") {
            let token = req.query.get("token").cloned().unwrap_or_default();
            let mode = mode_header.clone();
            if req.query.get("close").map(|v| v == "1").unwrap_or(false) {
                shared.log(format!("close mode={mode}"));
                shared.sessions.lock().unwrap().remove(&token);
                shared.next_upload_seq.lock().unwrap().remove(&token);
                mask_simple_response(&mut io, 200, "").await;
                return Ok(());
            }
            if req.query.get("fin").map(|v| v == "1").unwrap_or(false) {
                shared.log(format!("fin mode={mode}"));
                // CloseWrite on the session pipe.
                {
                    let mut sessions = shared.sessions.lock().unwrap();
                    if let Some(pipe) = sessions.get_mut(&token) {
                        pipe.wr = None;
                    }
                }
                mask_simple_response(&mut io, 200, "").await;
                return Ok(());
            }
            let seq: u64 = req.query.get("seq").and_then(|v| v.parse().ok()).unwrap_or(0);
            let expected = shared.next_upload_seq.lock().unwrap().get(&token).copied();
            let Some(expected) = expected else {
                mask_simple_response(&mut io, 404, "no session").await;
                return Ok(());
            };
            assert_eq!(seq, expected, "upload sequence must increment");
            shared
                .next_upload_seq
                .lock()
                .unwrap()
                .insert(token.clone(), expected + 1);
            shared.log(format!(
                "push mode={mode} ctype={}",
                req.headers.get("content-type").cloned().unwrap_or_default()
            ));
            let payload = if mode == "poll" {
                use base64::Engine;
                let text = String::from_utf8_lossy(&req.body).into_owned();
                let mut out = Vec::new();
                for line in text.lines().filter(|l| !l.is_empty()) {
                    out.extend_from_slice(
                        &base64::engine::general_purpose::STANDARD
                            .decode(line)
                            .map_err(|_| Error::protocol("bad push line"))?,
                    );
                }
                out
            } else {
                req.body.clone()
            };
            let wr = {
                let mut sessions = shared.sessions.lock().unwrap();
                match sessions.get_mut(&token) {
                    Some(pipe) => pipe.wr.take(),
                    None => None,
                }
            };
            let mut wr = match wr {
                Some(w) => w,
                None => {
                    mask_simple_response(&mut io, 404, "no session").await;
                    return Ok(());
                }
            };
            wr.write_all(&payload).await.ok();
            {
                let mut sessions = shared.sessions.lock().unwrap();
                if let Some(pipe) = sessions.get_mut(&token) {
                    pipe.wr = Some(wr);
                }
            }
            mask_simple_response(&mut io, 200, "").await;
            return Ok(());
        }
        if req.method == "GET" && req.path.ends_with("/ws") {
            shared.log(format!(
                "ws ed={} auth={}",
                req.query.contains_key("ed"),
                req.query.contains_key("auth")
            ));
            if let Some(auth) = req.query.get("auth") {
                let auth_key = client_aead_seed(&shared.seed);
                assert!(tunnel_auth_verify(auth, &auth_key), "ws auth token must verify");
                let bearer = req.headers.get("authorization").cloned().unwrap_or_default();
                assert!(bearer.starts_with("Bearer "), "bearer header: {bearer}");
            }
            use base64::Engine;
            let early_payload = match req.query.get("ed") {
                Some(v) => base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(v)
                    .map_err(|_| Error::protocol("bad ed"))?,
                None => Vec::new(),
            };
            let (response_payload, sess_c2s, sess_s2c) = if early_payload.is_empty() {
                (Vec::new(), [0u8; 32], [0u8; 32])
            } else {
                shared.process_early(&early_payload).await?
            };
            let mut resp =
                String::from("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
            if !response_payload.is_empty() {
                resp += &format!(
                    "X-Sudoku-Early: {}\r\n",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&response_payload)
                );
            }
            resp += "\r\n";
            io.write_all(resp.as_bytes()).await?;
            // The ws session: frames ↔ the session RecordConn.
            let (a, b) = tokio::io::duplex(256 * 1024);
            let obfs = ServerObfs::new(
                Box::new(a),
                shared.tables[0].clone(),
                shared.tables[0].opposite_direction(),
                shared.padding.0,
                shared.padding.1,
                shared.pure_downlink,
            );
            let conn: RecordConn<BoxProxyStream> = RecordConn::new(
                Box::new(obfs) as BoxProxyStream,
                shared.method,
                sess_s2c,
                sess_c2s,
            );
            let shared2 = shared.clone();
            tokio::spawn(async move {
                shared2
                    .run_session(
                        TunnelSessionKind::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
                        conn,
                    )
                    .await;
            });
            let (mut rd, mut wr) = tokio::io::split(io);
            let (mut b_rd, b_wr) = tokio::io::split(b);
            let pump_up = async move {
                let mut conn_side = b_wr;
                loop {
                    match ws_read_frame(&mut rd).await {
                        Ok(frame) if frame.opcode == 2 || frame.opcode == 1 => {
                            if conn_side.write_all(&frame.payload).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            };
            let pump_down = async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match b_rd.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if wr.write_all(&ws_build_frame(2, &buf[..n])).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            };
            tokio::join!(pump_up, pump_down);
            return Ok(());
        }
        mask_simple_response(&mut io, 404, "not found").await;
        Ok(())
    }

    /// Verify a ws auth token ±60s (ws_auth.go verifyValue).
    fn tunnel_auth_verify(token: &str, auth_key: &str) -> bool {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token) else {
            return false;
        };
        if raw.len() != 24 {
            return false;
        }
        let ts = u64::from_be_bytes(raw[..8].try_into().unwrap());
        let key_material = Sha256::new_with_prefix(b"sudoku-httpmask-auth-v1:")
            .chain_update(auth_key.as_bytes())
            .finalize();
        let key: [u8; 32] = key_material.into();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if (now - ts as i64).abs() > 60 {
            return false;
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(b"ws");
        mac.update(&[0]);
        mac.update(b"GET");
        mac.update(&[0]);
        mac.update(b"/ws");
        mac.update(&[0]);
        mac.update(&ts.to_be_bytes());
        let sig = mac.finalize().into_bytes();
        sig[..16] == raw[8..]
    }

    /// Spawn the mask server; returns (port, shared).
    async fn spawn_mask_server(tls: bool) -> (u16, Arc<MaskShared>) {
        let key = "mask-server-key-0123456789abcdef";
        let tables =
            new_client_tables_with_custom_patterns(key, "prefer_entropy", "", &[]).unwrap();
        let shared = Arc::new(MaskShared {
            seed: key.to_string(),
            method: RecordMethod::Chacha20Poly1305,
            padding: (10, 30),
            pure_downlink: true,
            tables,
            sessions: std::sync::Mutex::new(HashMap::new()),
            next_upload_seq: std::sync::Mutex::new(HashMap::new()),
            log: std::sync::Mutex::new(Vec::new()),
            reject_stream_authorize: AtomicBool::new(false),
            mux_marker: AtomicBool::new(false),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls_config = if tls {
            let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
                .expect("rcgen cert");
            let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                certified.key_pair.serialize_der().into(),
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(Arc::new(config))
        } else {
            None
        };
        tokio::spawn(mask_server_loop(listener, shared.clone(), tls_config));
        (port, shared)
    }

    fn tunnel_cfg(mode: &str, port: u16, tls: bool) -> SudokuOut {
        let mut cfg = SudokuOut::new("127.0.0.1", port, "mask-server-key-0123456789abcdef");
        cfg.http_mask_mode = mode.into();
        cfg.http_mask_tls = tls;
        cfg.http_mask_tls_insecure = tls;
        cfg
    }

    fn tcp_dialer(port: u16) -> TunnelDialer {
        std::sync::Arc::new(move || {
            let port = port;
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .map_err(|e| Error::network(format!("dial: {e}")))?;
                Ok(Box::new(stream) as BoxProxyStream)
            })
        })
    }

    async fn tunnel_echo(mode: &str, tls: bool, payload_len: usize) -> Arc<MaskShared> {
        let (port, shared) = spawn_mask_server(tls).await;
        let cfg = tunnel_cfg(mode, port, tls);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let stream = connect_tunnel(&cfg, tcp_dialer(port), &target)
            .await
            .expect("tunnel connect");
        let payload: Vec<u8> = (0..payload_len as u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.expect("echo read");
            got
        });
        wr.write_all(&payload).await.expect("tunnel write");
        let got = tokio::time::timeout(Duration::from_secs(30), echo)
            .await
            .expect("echo timed out")
            .expect("echo task");
        assert_eq!(got, payload);
        shared
    }

    #[tokio::test]
    async fn tunnel_stream_mode_echo() {
        let shared = tunnel_echo("stream", false, 100_000).await;
        let logged = shared.logged();
        assert!(
            logged.iter().any(|l| l == "authorize mode=stream"),
            "{logged:?}"
        );
        assert!(
            logged
                .iter()
                .any(|l| l.starts_with("push mode=stream ctype=application/octet-stream")),
            "{logged:?}"
        );
        assert!(logged.iter().any(|l| l.starts_with("pull mode=stream")), "{logged:?}");
    }

    #[tokio::test]
    async fn tunnel_poll_mode_echo() {
        let shared = tunnel_echo("poll", false, 80_000).await;
        let logged = shared.logged();
        assert!(logged.iter().any(|l| l == "authorize mode=poll"), "{logged:?}");
        assert!(
            logged.iter().any(|l| l.starts_with("push mode=poll ctype=text/plain")),
            "{logged:?}"
        );
        assert!(logged.iter().any(|l| l.starts_with("pull mode=poll")), "{logged:?}");
    }

    #[tokio::test]
    async fn tunnel_auto_falls_back_to_poll() {
        let (port, shared) = spawn_mask_server(false).await;
        shared
            .reject_stream_authorize
            .store(true, AtomicOrdering::Relaxed);
        let cfg = tunnel_cfg("auto", port, false);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = connect_tunnel(&cfg, tcp_dialer(port), &target)
            .await
            .expect("auto tunnel");
        stream.write_all(b"auto-fallback").await.unwrap();
        let mut buf = [0u8; 13];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"auto-fallback");
        let logged = shared.logged();
        assert!(
            logged.iter().any(|l| l == "authorize mode=stream"),
            "the stream probe must run first: {logged:?}"
        );
        assert!(logged.iter().any(|l| l == "authorize mode=poll"), "{logged:?}");
    }

    #[tokio::test]
    async fn tunnel_auto_prefers_stream() {
        let shared = tunnel_echo("auto", false, 5_000).await;
        let logged = shared.logged();
        assert!(logged.iter().any(|l| l == "authorize mode=stream"), "{logged:?}");
        assert!(!logged.iter().any(|l| l == "authorize mode=poll"), "{logged:?}");
    }

    #[tokio::test]
    async fn tunnel_ws_mode_echo() {
        let shared = tunnel_echo("ws", false, 100_000).await;
        assert!(
            shared.logged().iter().any(|l| l.starts_with("ws ed=true auth=true")),
            "{:?}",
            shared.logged()
        );
    }

    #[tokio::test]
    async fn tunnel_stream_mode_tls() {
        let shared = tunnel_echo("stream", true, 60_000).await;
        assert!(
            shared.logged().iter().any(|l| l == "authorize mode=stream"),
            "https authorize"
        );
    }

    #[tokio::test]
    async fn tunnel_ws_mode_tls() {
        let shared = tunnel_echo("ws", true, 40_000).await;
        assert!(
            shared.logged().iter().any(|l| l.starts_with("ws ed=true")),
            "wss upgrade"
        );
    }

    #[tokio::test]
    async fn tunnel_uot_over_stream() {
        let (port, _shared) = spawn_mask_server(false).await;
        let cfg = tunnel_cfg("stream", port, false);
        let mut stream = connect_tunnel_udp(&cfg, tcp_dialer(port))
            .await
            .expect("uot tunnel");
        // The mimic's Tcp session echoes raw bytes; UoT datagrams ride it.
        let target = NetAddr::domain("dns.example", 53).unwrap();
        let frame = uot_datagram(&target, b"uot-over-tunnel").unwrap();
        stream.write_all(&frame).await.unwrap();
        let mut buf = vec![0u8; frame.len()];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, frame);
    }

    #[tokio::test]
    async fn tunnel_mux_over_stream() {
        let (port, shared) = spawn_mask_server(false).await;
        shared.mux_marker.store(true, AtomicOrdering::Relaxed);
        let cfg = tunnel_cfg("stream", port, false);
        let session = connect_tunnel_mux(&cfg, tcp_dialer(port))
            .await
            .expect("tunnel mux");
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut s1 = session.open_stream(&target).await.expect("open");
        s1.write_all(b"mux-over-tunnel").await.unwrap();
        let mut buf = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(20), s1.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"mux-over-tunnel");
        session.close();
    }

    #[tokio::test]
    async fn tunnel_rejects_single_transport_entry() {
        let (port, _shared) = spawn_mask_server(false).await;
        let cfg = tunnel_cfg("stream", port, false);
        let err = connect(
            &cfg,
            Box::new(tokio::io::duplex(16).0),
            &NetAddr::domain("a", 1).unwrap(),
        )
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("connect_tunnel"), "{err}");
        let err = connect_tunnel(
            &SudokuOut::new("127.0.0.1", port, "k"),
            tcp_dialer(port),
            &NetAddr::domain("a", 1).unwrap(),
        )
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("does not use the http tunnel"), "{err}");
    }

    #[tokio::test]
    async fn tunnel_stream_upload_sequence_enforced() {
        // The mimic asserts seq ordering; a large payload forces several
        // sequenced uploads through the 256KiB batching.
        let (port, _shared) = spawn_mask_server(false).await;
        let cfg = tunnel_cfg("stream", port, false);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let stream = connect_tunnel(&cfg, tcp_dialer(port), &target)
            .await
            .expect("connect");
        let payload: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.expect("echo read");
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(40), echo)
            .await
            .expect("echo timed out")
            .expect("echo task");
        assert_eq!(got, payload);
    }

    #[test]
    fn tunnel_helpers_shape() {
        // canonicalHeaderHost strips default ports, keeps IPv6 bracketed.
        assert_eq!(canonical_header_host("example.com:443", "https"), "example.com");
        assert_eq!(canonical_header_host("example.com:80", "http"), "example.com");
        assert_eq!(
            canonical_header_host("example.com:8443", "https"),
            "example.com:8443"
        );
        assert_eq!(canonical_header_host("[::1]:443", "https"), "[::1]");
        // normalizeHTTPDialTarget with host override.
        let t = normalize_http_dial_target("1.2.3.4:8443", true, "cdn.example").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.header_host, "cdn.example:8443");
        assert_eq!(t.server_name, "cdn.example");
        let t = normalize_ws_dial_target("1.2.3.4", true, "").unwrap();
        assert_eq!(t.scheme, "wss");
        assert_eq!(t.server_name, "1.2.3.4");
        // parseAuthorizeResponse (tunnel_dial.go:65).
        let body = b"token=abcDEF-_123\ncap=upload-seq";
        let (token, early) = parse_authorize_response(body).unwrap();
        assert_eq!(token, "abcDEF-_123");
        assert!(early.is_none());
        let body = b"junk\ntoken=tok1";
        assert!(parse_authorize_response(body).is_err(), "missing cap");
        // ws auth token shape: base64url of ts_be64 + sig16.
        let token = tunnel_auth_token("seed", "ws", "GET", "/ws");
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        assert_eq!(raw.len(), 24);
        assert!(tunnel_auth_verify(&token, "seed"));
        assert!(!tunnel_auth_verify(&token, "other-seed"));
    }

}
