package jose

import (
	"encoding/json"
	"testing"
)

// TestGenerateKey calls jose.GenerateKey with an algorithm and a seed
// and confirms the resulting JWK is well formed
func TestGenerateKey(t *testing.T) {
	var alg = "ML-DSA-44"
	var seed [32]byte // zero seed
	var jwk, err = GenerateKey(alg, seed[:])
	if err != nil {
		t.Fatalf(`Failed to serialize JWK`)
	}
	var decoded AKPKey
	json.Unmarshal([]byte(jwk), &decoded)

	if decoded.Alg != alg {
		t.Fatalf(`JWK did not contain expected alg (%s)`, alg)
	}
	if decoded.Kty != "AKP" {
		t.Fatalf(`JWK did not contain expected kty (AKP)`)
	}
	if len(decoded.Pub) != 1750 {
		t.Fatalf(`JWK pub length not expected (%d), want 1750`, len(decoded.Pub))
	}
	if len(decoded.Seed) != 43 {
		t.Fatalf(`JWK seed length not expected (%d), want 43`, len(decoded.Seed))
	}
	if decoded.Kid != "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o" { // for ML-DSA-44 all zeros private key
		t.Fatalf(`JWK did not have expected thumbprint (%s), want T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o`, decoded.Kid)
	}
}

// TestCalculateJwkThumbprint calls jose.CalculateJwkThumbprint with JWKs
// and confirms the resulting thumbprints are computed correctly
func TestCalculateJwkThumbprint(t *testing.T) {
	var k1 = `{"kty":"EC","crv":"P-256","x":"zQwCN0Q1A2OF-vzRFYMDTThEjkSl3o6vSonhDQwHHz4","y":"ahiGLX7rLYv4DIlKk017zC-zqgzexrxoVuQvaJuObzA"}`
	var t1, _ = CalculateJwkThumbprint(k1)
	if t1 != "sF8ijcZ3yIRTT6M9vtM_jMouZZKTtlkCM5BwbK75mck" {
		t.Fatalf(`Incorrect JWK thumbprint(%s), want sF8ijcZ3yIRTT6M9vtM_jMouZZKTtlkCM5BwbK75mck`, t1)
	}
	var k2 = `{"kty":"AKP","alg":"ML-DSA-44","pub":"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ","priv":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	var t2, _ = CalculateJwkThumbprint(k2)
	if t2 != "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o" {
		t.Fatalf(`Incorrect JWK thumbprint(%s), want T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o`, t2)
	}
}
