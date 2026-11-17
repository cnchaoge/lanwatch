//! Exit place names for the public address on the NAT line.
//!
//! The country code comes from the Team Cymru origin TXT the path lookup already
//! reads. The city, when one is known, comes only from [`CITY_RANGES`] shipped
//! with the program. Nothing here contacts a geolocation HTTP API.

use std::net::Ipv4Addr;

pub fn country_zh(code: &str) -> String {
    let code = code.trim();
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    let code = code.to_ascii_uppercase();
    COUNTRIES
        .iter()
        .find(|(cc, _)| *cc == code)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_default()
}

struct CityRange {
    start: u32,
    end: u32,
    city: &'static str,
}

/// Inclusive IPv4 ranges, sorted by start and not overlapping.
/// An empty table means the NAT line carries the country only.
const CITY_RANGES: &[CityRange] = &[];

pub fn city_for(ip: &str) -> String {
    find_city(ip, CITY_RANGES).to_string()
}

fn find_city<'a>(ip: &str, rows: &'a [CityRange]) -> &'a str {
    if rows.is_empty() {
        return "";
    }
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return "";
    };
    let n = u32::from(addr);
    let mut lo = 0usize;
    let mut hi = rows.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if n < rows[mid].start {
            hi = mid;
        } else if n > rows[mid].end {
            lo = mid + 1;
        } else {
            return rows[mid].city;
        }
    }
    ""
}

const COUNTRIES: &[(&str, &str)] = &[
    ("AD", "安道尔"),
    ("AE", "阿联酋"),
    ("AF", "阿富汗"),
    ("AG", "安提瓜和巴布达"),
    ("AI", "安圭拉"),
    ("AL", "阿尔巴尼亚"),
    ("AM", "亚美尼亚"),
    ("AO", "安哥拉"),
    ("AQ", "南极洲"),
    ("AR", "阿根廷"),
    ("AS", "美属萨摩亚"),
    ("AT", "奥地利"),
    ("AU", "澳大利亚"),
    ("AW", "阿鲁巴"),
    ("AX", "奥兰群岛"),
    ("AZ", "阿塞拜疆"),
    ("BA", "波黑"),
    ("BB", "巴巴多斯"),
    ("BD", "孟加拉国"),
    ("BE", "比利时"),
    ("BF", "布基纳法索"),
    ("BG", "保加利亚"),
    ("BH", "巴林"),
    ("BI", "布隆迪"),
    ("BJ", "贝宁"),
    ("BL", "圣巴泰勒米"),
    ("BM", "百慕大"),
    ("BN", "文莱"),
    ("BO", "玻利维亚"),
    ("BQ", "荷兰加勒比"),
    ("BR", "巴西"),
    ("BS", "巴哈马"),
    ("BT", "不丹"),
    ("BV", "布韦岛"),
    ("BW", "博茨瓦纳"),
    ("BY", "白俄罗斯"),
    ("BZ", "伯利兹"),
    ("CA", "加拿大"),
    ("CC", "科科斯群岛"),
    ("CD", "刚果（金）"),
    ("CF", "中非"),
    ("CG", "刚果（布）"),
    ("CH", "瑞士"),
    ("CI", "科特迪瓦"),
    ("CK", "库克群岛"),
    ("CL", "智利"),
    ("CM", "喀麦隆"),
    ("CN", "中国"),
    ("CO", "哥伦比亚"),
    ("CR", "哥斯达黎加"),
    ("CU", "古巴"),
    ("CV", "佛得角"),
    ("CW", "库拉索"),
    ("CX", "圣诞岛"),
    ("CY", "塞浦路斯"),
    ("CZ", "捷克"),
    ("DE", "德国"),
    ("DJ", "吉布提"),
    ("DK", "丹麦"),
    ("DM", "多米尼克"),
    ("DO", "多米尼加"),
    ("DZ", "阿尔及利亚"),
    ("EC", "厄瓜多尔"),
    ("EE", "爱沙尼亚"),
    ("EG", "埃及"),
    ("EH", "西撒哈拉"),
    ("ER", "厄立特里亚"),
    ("ES", "西班牙"),
    ("ET", "埃塞俄比亚"),
    ("FI", "芬兰"),
    ("FJ", "斐济"),
    ("FK", "福克兰群岛"),
    ("FM", "密克罗尼西亚"),
    ("FO", "法罗群岛"),
    ("FR", "法国"),
    ("GA", "加蓬"),
    ("GB", "英国"),
    ("GD", "格林纳达"),
    ("GE", "格鲁吉亚"),
    ("GF", "法属圭亚那"),
    ("GG", "根西岛"),
    ("GH", "加纳"),
    ("GI", "直布罗陀"),
    ("GL", "格陵兰"),
    ("GM", "冈比亚"),
    ("GN", "几内亚"),
    ("GP", "瓜德罗普"),
    ("GQ", "赤道几内亚"),
    ("GR", "希腊"),
    ("GS", "南乔治亚和南桑威奇群岛"),
    ("GT", "危地马拉"),
    ("GU", "关岛"),
    ("GW", "几内亚比绍"),
    ("GY", "圭亚那"),
    ("HK", "香港"),
    ("HM", "赫德岛和麦克唐纳群岛"),
    ("HN", "洪都拉斯"),
    ("HR", "克罗地亚"),
    ("HT", "海地"),
    ("HU", "匈牙利"),
    ("ID", "印度尼西亚"),
    ("IE", "爱尔兰"),
    ("IL", "以色列"),
    ("IM", "马恩岛"),
    ("IN", "印度"),
    ("IO", "英属印度洋领地"),
    ("IQ", "伊拉克"),
    ("IR", "伊朗"),
    ("IS", "冰岛"),
    ("IT", "意大利"),
    ("JE", "泽西岛"),
    ("JM", "牙买加"),
    ("JO", "约旦"),
    ("JP", "日本"),
    ("KE", "肯尼亚"),
    ("KG", "吉尔吉斯斯坦"),
    ("KH", "柬埔寨"),
    ("KI", "基里巴斯"),
    ("KM", "科摩罗"),
    ("KN", "圣基茨和尼维斯"),
    ("KP", "朝鲜"),
    ("KR", "韩国"),
    ("KW", "科威特"),
    ("KY", "开曼群岛"),
    ("KZ", "哈萨克斯坦"),
    ("LA", "老挝"),
    ("LB", "黎巴嫩"),
    ("LC", "圣卢西亚"),
    ("LI", "列支敦士登"),
    ("LK", "斯里兰卡"),
    ("LR", "利比里亚"),
    ("LS", "莱索托"),
    ("LT", "立陶宛"),
    ("LU", "卢森堡"),
    ("LV", "拉脱维亚"),
    ("LY", "利比亚"),
    ("MA", "摩洛哥"),
    ("MC", "摩纳哥"),
    ("MD", "摩尔多瓦"),
    ("ME", "黑山"),
    ("MF", "法属圣马丁"),
    ("MG", "马达加斯加"),
    ("MH", "马绍尔群岛"),
    ("MK", "北马其顿"),
    ("ML", "马里"),
    ("MM", "缅甸"),
    ("MN", "蒙古"),
    ("MO", "澳门"),
    ("MP", "北马里亚纳群岛"),
    ("MQ", "马提尼克"),
    ("MR", "毛里塔尼亚"),
    ("MS", "蒙特塞拉特"),
    ("MT", "马耳他"),
    ("MU", "毛里求斯"),
    ("MV", "马尔代夫"),
    ("MW", "马拉维"),
    ("MX", "墨西哥"),
    ("MY", "马来西亚"),
    ("MZ", "莫桑比克"),
    ("NA", "纳米比亚"),
    ("NC", "新喀里多尼亚"),
    ("NE", "尼日尔"),
    ("NF", "诺福克岛"),
    ("NG", "尼日利亚"),
    ("NI", "尼加拉瓜"),
    ("NL", "荷兰"),
    ("NO", "挪威"),
    ("NP", "尼泊尔"),
    ("NR", "瑙鲁"),
    ("NU", "纽埃"),
    ("NZ", "新西兰"),
    ("OM", "阿曼"),
    ("PA", "巴拿马"),
    ("PE", "秘鲁"),
    ("PF", "法属波利尼西亚"),
    ("PG", "巴布亚新几内亚"),
    ("PH", "菲律宾"),
    ("PK", "巴基斯坦"),
    ("PL", "波兰"),
    ("PM", "圣皮埃尔和密克隆"),
    ("PN", "皮特凯恩群岛"),
    ("PR", "波多黎各"),
    ("PS", "巴勒斯坦"),
    ("PT", "葡萄牙"),
    ("PW", "帕劳"),
    ("PY", "巴拉圭"),
    ("QA", "卡塔尔"),
    ("RE", "留尼汪"),
    ("RO", "罗马尼亚"),
    ("RS", "塞尔维亚"),
    ("RU", "俄罗斯"),
    ("RW", "卢旺达"),
    ("SA", "沙特阿拉伯"),
    ("SB", "所罗门群岛"),
    ("SC", "塞舌尔"),
    ("SD", "苏丹"),
    ("SE", "瑞典"),
    ("SG", "新加坡"),
    ("SH", "圣赫勒拿"),
    ("SI", "斯洛文尼亚"),
    ("SJ", "斯瓦尔巴和扬马延"),
    ("SK", "斯洛伐克"),
    ("SL", "塞拉利昂"),
    ("SM", "圣马力诺"),
    ("SN", "塞内加尔"),
    ("SO", "索马里"),
    ("SR", "苏里南"),
    ("SS", "南苏丹"),
    ("ST", "圣多美和普林西比"),
    ("SV", "萨尔瓦多"),
    ("SX", "荷属圣马丁"),
    ("SY", "叙利亚"),
    ("SZ", "斯威士兰"),
    ("TC", "特克斯和凯科斯群岛"),
    ("TD", "乍得"),
    ("TF", "法属南部领地"),
    ("TG", "多哥"),
    ("TH", "泰国"),
    ("TJ", "塔吉克斯坦"),
    ("TK", "托克劳"),
    ("TL", "东帝汶"),
    ("TM", "土库曼斯坦"),
    ("TN", "突尼斯"),
    ("TO", "汤加"),
    ("TR", "土耳其"),
    ("TT", "特立尼达和多巴哥"),
    ("TV", "图瓦卢"),
    ("TW", "台湾"),
    ("TZ", "坦桑尼亚"),
    ("UA", "乌克兰"),
    ("UG", "乌干达"),
    ("UM", "美国本土外小岛屿"),
    ("US", "美国"),
    ("UY", "乌拉圭"),
    ("UZ", "乌兹别克斯坦"),
    ("VA", "梵蒂冈"),
    ("VC", "圣文森特和格林纳丁斯"),
    ("VE", "委内瑞拉"),
    ("VG", "英属维尔京群岛"),
    ("VI", "美属维尔京群岛"),
    ("VN", "越南"),
    ("VU", "瓦努阿图"),
    ("WF", "瓦利斯和富图纳"),
    ("WS", "萨摩亚"),
    ("YE", "也门"),
    ("YT", "马约特"),
    ("ZA", "南非"),
    ("ZM", "赞比亚"),
    ("ZW", "津巴布韦"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes_become_chinese_names() {
        assert_eq!(country_zh("CN"), "中国");
        assert_eq!(country_zh("cn"), "中国");
        assert_eq!(country_zh("US"), "美国");
        assert_eq!(country_zh("HK"), "香港");
        assert_eq!(country_zh("JP"), "日本");
        assert_eq!(country_zh(""), "");
        assert_eq!(country_zh("ZZ"), "");
        assert_eq!(country_zh("CHN"), "");
        assert!(!country_zh("CN").contains("CN"));
    }

    #[test]
    fn a_local_range_adds_a_city_and_a_miss_stays_empty() {
        let rows = [
            CityRange {
                start: u32::from(Ipv4Addr::new(198, 51, 100, 0)),
                end: u32::from(Ipv4Addr::new(198, 51, 100, 10)),
                city: "北京",
            },
            CityRange {
                start: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                end: u32::from(Ipv4Addr::new(203, 0, 113, 255)),
                city: "上海",
            },
        ];
        assert_eq!(find_city("203.0.113.8", &rows), "上海");
        assert_eq!(find_city("198.51.100.10", &rows), "北京");
        assert_eq!(find_city("198.51.100.11", &rows), "");
        assert_eq!(find_city("1.1.1.1", &rows), "");
        assert_eq!(find_city("not-an-ip", &rows), "");
        assert_eq!(city_for("203.0.113.8"), "");
    }
}
