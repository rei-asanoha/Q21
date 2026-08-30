//! JSON minimal.
//!
//! Assez pour une API JSON-RPC, pas un octet de plus. Ecrit ici plutot
//! qu'importe pour la meme raison que le reste : ce module lit des donnees
//! venues d'un client quelconque, et une dependance qu'on n'a pas relue est une
//! surface d'attaque qu'on ne connait pas.
//!
//! # Ce qui est volontairement absent
//!
//! Pas de flottants. Une API qui expose des montants monetaires ne doit jamais
//! les faire transiter en `double` : `0.1 + 0.2 != 0.3` en IEEE 754, et un
//! client naif qui relit un solde ainsi encode perd des unites. Les montants
//! sortent en entier d'unites indivisibles **et** en chaine formatee. Le client
//! choisit, mais aucune conversion approximative n'a lieu de notre cote.
//!
//! # Bornes
//!
//! La profondeur d'imbrication et la taille du document sont bornees a l'analyse.
//! Sans cela, `[[[[[...]]]]]` sur quelques mégaoctets fait exploser la pile par
//! recursion — un deni de service qui tient en une ligne de `curl`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Profondeur d'imbrication maximale acceptee.
pub const MAX_DEPTH: usize = 32;

/// Taille maximale d'un document analyse, en octets.
pub const MAX_INPUT: usize = 1024 * 1024;

/// Valeur JSON.
///
/// Les objets sont ordonnes : deux encodages du meme objet sont identiques,
/// ce qui rend les tests deterministes et les reponses diffables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Entier signe. Aucun flottant n'existe dans ce module, par choix.
    Int(i64),
    /// Entier non signe au-dela de `i64::MAX`.
    ///
    /// Encode comme un **nombre**, jamais comme une chaine : un champ
    /// numerique qui change de type selon sa valeur est un piege pour tout
    /// client, et le pont vers une injection quand ce client insere la valeur
    /// dans une page.
    Grand(u64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> JsonObj {
        JsonObj(BTreeMap::new())
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn int(v: impl Into<i64>) -> Json {
        Json::Int(v.into())
    }

    /// Entier non signe 64 bits.
    ///
    /// Au-dela de `i64::MAX` on passe en chaine plutot que de tronquer : une
    /// valeur monetaire fausse est pire qu'une valeur d'un autre type.
    /// Un entier reste un entier.
    ///
    /// Cette fonction basculait en **chaine** au-dela de `i64::MAX`. Un champ
    /// que le client croit numerique changeait donc de type sans prevenir : la
    /// valeur passait dans un point d'insertion prevu pour un nombre, ou dans
    /// une comparaison qui ne comparait plus rien. C'est le pont entre un
    /// compteur et une injection.
    ///
    /// JSON ne borne pas les entiers ; c'est JavaScript qui perd la precision
    /// au-dela de 2^53. Le type, lui, ne doit pas varier.
    pub fn u64(v: u64) -> Json {
        if v <= i64::MAX as u64 {
            Json::Int(v as i64)
        } else {
            Json::Grand(v)
        }
    }

    pub fn array(v: Vec<Json>) -> Json {
        Json::Array(v)
    }

    pub fn get(&self, clef: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(clef),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Un champ numerique doit arriver comme un nombre.
    ///
    /// Cette fonction acceptait une **chaine** et la convertissait. La borne
    /// que l'analyseur pose sur les entiers — `i64::MAX` — se contournait donc
    /// en mettant le nombre entre guillemets, et c'est par la qu'un
    /// `sendtoaddress` faisait deborder une addition et arretait le noeud.
    ///
    /// Rien de legitime n'a besoin de cette tolerance.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(v) if *v >= 0 => Some(*v as u64),
            Json::Grand(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Encode en JSON compact.
    pub fn encode(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(v) => {
                let _ = write!(out, "{v}");
            }
            Json::Grand(v) => {
                let _ = write!(out, "{v}");
            }
            Json::Str(s) => echapper(s, out),
            Json::Array(v) => {
                out.push('[');
                for (i, e) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    e.write(out);
                }
                out.push(']');
            }
            Json::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    echapper(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Constructeur d'objet, pour ecrire les reponses sans ceremonie.
pub struct JsonObj(BTreeMap<String, Json>);

impl JsonObj {
    pub fn set(mut self, clef: &str, v: Json) -> JsonObj {
        self.0.insert(clef.to_string(), v);
        self
    }
    /// Pose plusieurs champs d'un coup — pratique pour greffer un groupe
    /// calcule a part sans casser le chainage.
    pub fn set_all<'a>(mut self, champs: impl IntoIterator<Item = (&'a str, Json)>) -> JsonObj {
        for (clef, v) in champs {
            self.0.insert(clef.to_string(), v);
        }
        self
    }
    pub fn build(self) -> Json {
        Json::Object(self.0)
    }
}

/// Echappe une chaine selon RFC 8259.
///
/// Les caracteres de controle doivent etre echappes ; les oublier produit un
/// document que la moitie des analyseurs refusent et que l'autre interprete
/// differemment.
fn echapper(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            // --- Sortie sure quel que soit le contexte d'insertion.
            //
            // `<`, `>` et `/` permettent de refermer un `<script>` depuis une
            // chaine JSON placee dans une page. U+2028 et U+2029 sont des fins
            // de ligne pour JavaScript, mais pas pour JSON : une chaine qui en
            // contient casse un `<script>` qui l'incorpore.
            //
            // Ces echappements restent du JSON parfaitement standard : tout
            // analyseur les relit a l'identique. Ils ne coutent rien et ils
            // ferment une classe entiere de problemes chez nos clients.
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '/' => out.push_str("\\u002f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum JsonError {
    DocumentTropGrand(usize),
    ImbricationTropProfonde,
    CaractereInattendu {
        position: usize,
        trouve: char,
    },
    FinPrematuree,
    NombreInvalide,
    EchappementInvalide,
    OctetsRestants,
    /// Deux fois la meme clef dans un objet : document ambigu.
    ClefDupliquee(String),
}

/// Analyse un document JSON.
pub fn parse(entree: &str) -> Result<Json, JsonError> {
    if entree.len() > MAX_INPUT {
        return Err(JsonError::DocumentTropGrand(entree.len()));
    }
    let octets: Vec<char> = entree.chars().collect();
    let mut p = Analyseur {
        c: &octets,
        i: 0,
        profondeur: 0,
    };
    p.espaces();
    let v = p.valeur()?;
    p.espaces();
    if p.i != p.c.len() {
        return Err(JsonError::OctetsRestants);
    }
    Ok(v)
}

struct Analyseur<'a> {
    c: &'a [char],
    i: usize,
    profondeur: usize,
}

impl Analyseur<'_> {
    fn espaces(&mut self) {
        while self.i < self.c.len() && matches!(self.c[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }

    fn courant(&self) -> Result<char, JsonError> {
        self.c.get(self.i).copied().ok_or(JsonError::FinPrematuree)
    }

    fn attendu(&mut self, c: char) -> Result<(), JsonError> {
        if self.courant()? != c {
            return Err(JsonError::CaractereInattendu {
                position: self.i,
                trouve: self.c[self.i],
            });
        }
        self.i += 1;
        Ok(())
    }

    fn litteral(&mut self, mot: &str) -> Result<(), JsonError> {
        for c in mot.chars() {
            self.attendu(c)?;
        }
        Ok(())
    }

    fn valeur(&mut self) -> Result<Json, JsonError> {
        // Le compteur de profondeur est la seule chose qui empeche
        // `[[[[[[...]]]]]]` de faire deborder la pile.
        if self.profondeur > MAX_DEPTH {
            return Err(JsonError::ImbricationTropProfonde);
        }
        match self.courant()? {
            'n' => {
                self.litteral("null")?;
                Ok(Json::Null)
            }
            't' => {
                self.litteral("true")?;
                Ok(Json::Bool(true))
            }
            'f' => {
                self.litteral("false")?;
                Ok(Json::Bool(false))
            }
            '"' => Ok(Json::Str(self.chaine()?)),
            '[' => self.tableau(),
            '{' => self.objet(),
            c if c == '-' || c.is_ascii_digit() => self.nombre(),
            c => Err(JsonError::CaractereInattendu {
                position: self.i,
                trouve: c,
            }),
        }
    }

    fn chaine(&mut self) -> Result<String, JsonError> {
        self.attendu('"')?;
        let mut s = String::new();
        loop {
            let c = self.courant()?;
            self.i += 1;
            match c {
                '"' => return Ok(s),
                '\\' => {
                    let e = self.courant()?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'b' => s.push('\u{08}'),
                        'f' => s.push('\u{0c}'),
                        'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let h = self.courant()?;
                                self.i += 1;
                                code = code * 16
                                    + h.to_digit(16).ok_or(JsonError::EchappementInvalide)?;
                            }
                            s.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(JsonError::EchappementInvalide),
                    }
                }
                c => s.push(c),
            }
        }
    }

    fn nombre(&mut self) -> Result<Json, JsonError> {
        let debut = self.i;
        if self.courant()? == '-' {
            self.i += 1;
        }
        while self.i < self.c.len() && self.c[self.i].is_ascii_digit() {
            self.i += 1;
        }
        // Un JSON contenant un flottant est refuse plutot qu'arrondi : mieux
        // vaut une erreur franche qu'un montant silencieusement faux.
        if self.i < self.c.len() && matches!(self.c[self.i], '.' | 'e' | 'E') {
            return Err(JsonError::NombreInvalide);
        }
        let texte: String = self.c[debut..self.i].iter().collect();
        if let Ok(v) = texte.parse::<i64>() {
            return Ok(Json::Int(v));
        }
        // Entre `i64::MAX` et `u64::MAX` : un nombre parfaitement valide en
        // JSON, que ce module represente a part plutot que de le refuser ou de
        // le convertir en chaine.
        texte
            .parse::<u64>()
            .map(Json::Grand)
            .map_err(|_| JsonError::NombreInvalide)
    }

    fn tableau(&mut self) -> Result<Json, JsonError> {
        self.attendu('[')?;
        self.profondeur += 1;
        let mut v = Vec::new();
        self.espaces();
        if self.courant()? == ']' {
            self.i += 1;
            self.profondeur -= 1;
            return Ok(Json::Array(v));
        }
        loop {
            self.espaces();
            v.push(self.valeur()?);
            self.espaces();
            match self.courant()? {
                ',' => self.i += 1,
                ']' => {
                    self.i += 1;
                    self.profondeur -= 1;
                    return Ok(Json::Array(v));
                }
                c => {
                    return Err(JsonError::CaractereInattendu {
                        position: self.i,
                        trouve: c,
                    })
                }
            }
        }
    }

    fn objet(&mut self) -> Result<Json, JsonError> {
        self.attendu('{')?;
        self.profondeur += 1;
        let mut m = BTreeMap::new();
        self.espaces();
        if self.courant()? == '}' {
            self.i += 1;
            self.profondeur -= 1;
            return Ok(Json::Object(m));
        }
        loop {
            self.espaces();
            let k = self.chaine()?;
            self.espaces();
            self.attendu(':')?;
            self.espaces();
            let v = self.valeur()?;
            // --- Une clef repetee est un document ambigu, donc refuse.
            //
            // `BTreeMap::insert` faisait gagner la **derniere** occurrence.
            // Un intermediaire — pare-feu applicatif, journal d'audit,
            // mandataire filtrant — qui lit la premiere voit alors autre chose
            // que le noeud. C'est exactement le motif de la « contrebande de
            // requetes », transpose au JSON : deux lecteurs, deux verites, une
            // depense qui passe.
            //
            // Le RFC 8259 laisse le comportement indefini. Un code monetaire ne
            // se paie pas d'indefini.
            if m.contains_key(&k) {
                return Err(JsonError::ClefDupliquee(k));
            }
            m.insert(k, v);
            self.espaces();
            match self.courant()? {
                ',' => self.i += 1,
                '}' => {
                    self.i += 1;
                    self.profondeur -= 1;
                    return Ok(Json::Object(m));
                }
                c => {
                    return Err(JsonError::CaractereInattendu {
                        position: self.i,
                        trouve: c,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodage_des_valeurs_simples() {
        assert_eq!(Json::Null.encode(), "null");
        assert_eq!(Json::Bool(true).encode(), "true");
        assert_eq!(Json::Int(-42).encode(), "-42");
        assert_eq!(Json::str("bonjour").encode(), "\"bonjour\"");
    }

    #[test]
    fn les_objets_sont_ordonnes() {
        let a = Json::obj()
            .set("z", Json::Int(1))
            .set("a", Json::Int(2))
            .build();
        let b = Json::obj()
            .set("a", Json::Int(2))
            .set("z", Json::Int(1))
            .build();
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.encode(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn echappement_conforme() {
        assert_eq!(Json::str("a\"b").encode(), r#""a\"b""#);
        assert_eq!(Json::str("a\\b").encode(), r#""a\\b""#);
        assert_eq!(Json::str("a\nb").encode(), r#""a\nb""#);
        // Caractere de controle : echappement \\u obligatoire. L'omettre produit
        // un document que la moitie des analyseurs refusent et que l'autre
        // interprete differemment.
        assert_eq!(Json::str("a\u{1}b").encode(), r#""a\u0001b""#);
        assert_eq!(Json::str("accentué").encode(), "\"accentué\"");
    }

    /// Un entier reste un entier, quelle que soit sa taille.
    ///
    /// Il basculait en chaine au-dela de `i64::MAX` : un champ numerique
    /// changeait donc de type selon sa valeur, ce qui piege tout client — et
    /// ouvre une injection chez celui qui insere la valeur dans une page.
    #[test]
    fn un_grand_entier_non_signe_reste_un_nombre() {
        assert_eq!(Json::u64(42).encode(), "42");
        assert_eq!(Json::u64(u64::MAX).encode(), "18446744073709551615");
        // Et il se relit a l'identique.
        let relu = parse(&Json::u64(u64::MAX).encode()).unwrap();
        assert_eq!(relu.as_u64(), Some(u64::MAX));
    }

    #[test]
    fn aller_retour_sur_un_document_realiste() {
        let v = Json::obj()
            .set("hauteur", Json::u64(206))
            .set("tete", Json::str("abcdef"))
            .set(
                "pairs",
                Json::array(vec![Json::str("127.0.0.1:21031"), Json::Null]),
            )
            .set("synchronise", Json::Bool(true))
            .build();
        assert_eq!(parse(&v.encode()).unwrap(), v);
    }

    #[test]
    fn analyse_des_cas_courants() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("  true  ").unwrap(), Json::Bool(true));
        assert_eq!(parse("-17").unwrap(), Json::Int(-17));
        assert_eq!(parse("[]").unwrap(), Json::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), Json::Object(BTreeMap::new()));
        assert_eq!(
            parse(r#"{"a":[1,2,{"b":null}]}"#).unwrap().encode(),
            r#"{"a":[1,2,{"b":null}]}"#
        );
    }

    #[test]
    fn les_echappements_se_relisent() {
        assert_eq!(parse(r#""a\nb""#).unwrap(), Json::str("a\nb"));
        assert_eq!(parse(r#""A""#).unwrap(), Json::str("A"));
        assert_eq!(parse(r#""\\""#).unwrap(), Json::str("\\"));
    }

    /// Un flottant refuse franchement vaut mieux qu'un montant arrondi.
    #[test]
    fn les_flottants_sont_refuses() {
        assert_eq!(parse("1.5"), Err(JsonError::NombreInvalide));
        assert_eq!(parse("1e10"), Err(JsonError::NombreInvalide));
    }

    /// Le controle qui empeche un deni de service en une ligne de curl.
    #[test]
    fn une_imbrication_absurde_est_refusee_sans_deborder_la_pile() {
        let profond = "[".repeat(1000) + &"]".repeat(1000);
        assert_eq!(parse(&profond), Err(JsonError::ImbricationTropProfonde));
    }

    #[test]
    fn un_document_trop_grand_est_refuse() {
        let gros = "\"".to_string() + &"a".repeat(MAX_INPUT) + "\"";
        assert!(matches!(parse(&gros), Err(JsonError::DocumentTropGrand(_))));
    }

    #[test]
    fn les_documents_malformes_sont_refuses() {
        assert!(parse("").is_err());
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse(r#"{"a"}"#).is_err());
        assert!(parse("truc").is_err());
        assert_eq!(parse("1 2"), Err(JsonError::OctetsRestants));
    }

    /// Aucune entree, si tordue soit-elle, ne doit faire paniquer.
    #[test]
    fn aucune_entree_aleatoire_ne_fait_paniquer() {
        let alphabet: Vec<char> = "{}[]\",:0123456789tfnul \\/-.eE\u{e9}".chars().collect();
        let mut graine = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..5_000 {
            graine = graine
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let n = (graine % 60) as usize;
            let mut s = String::new();
            let mut g = graine;
            for _ in 0..n {
                g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                s.push(alphabet[(g >> 33) as usize % alphabet.len()]);
            }
            let _ = parse(&s);
        }
    }

    #[test]
    fn accesseurs() {
        let v = parse(r#"{"n":7,"s":"x","t":[1,2],"grand":18446744073709551615}"#).unwrap();
        assert_eq!(v.get("n").and_then(|x| x.as_u64()), Some(7));
        assert_eq!(v.get("s").and_then(|x| x.as_str()), Some("x"));
        assert_eq!(
            v.get("t").and_then(|x| x.as_array()).map(|a| a.len()),
            Some(2)
        );
        assert_eq!(
            v.get("grand").and_then(|x| x.as_u64()),
            Some(u64::MAX),
            "un grand entier doit se relire comme nombre"
        );
        // Et une chaine n'est **pas** un nombre : c'est par cette tolerance
        // qu'un `sendtoaddress` faisait deborder une addition.
        let v = parse(r#"{"n":"18446744073709551615"}"#).unwrap();
        assert_eq!(
            v.get("n").and_then(|x| x.as_u64()),
            None,
            "une chaine ne doit pas etre acceptee comme entier"
        );
        // Une clef repetee rend le document ambigu : refuse.
        assert!(matches!(
            parse(r#"{"method":"getinfo","method":"sendtoaddress"}"#),
            Err(JsonError::ClefDupliquee(_))
        ));
        assert!(v.get("absent").is_none());
    }
}
