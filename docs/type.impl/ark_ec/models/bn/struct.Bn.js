(function() {var type_impls = {
"fastcrypto_zkp":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Clone-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; Bn&lt;P&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.77.1/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.1/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.77.1/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<section id=\"impl-Eq-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Eq-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section>","Eq","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-PartialEq-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;Bn&lt;P&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.1/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<section id=\"impl-Copy-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Copy-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section>","Copy","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Pairing-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Pairing-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; Pairing for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.BaseField\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.BaseField\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">BaseField</a> = &lt;&lt;P as BnConfig&gt;::G1Config as CurveConfig&gt;::BaseField</h4></section></summary><div class='docblock'>This is the base field of the G1 group and base prime field of G2.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.ScalarField\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.ScalarField\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">ScalarField</a> = &lt;&lt;P as BnConfig&gt;::G1Config as CurveConfig&gt;::ScalarField</h4></section></summary><div class='docblock'>This is the scalar field of the G1/G2 groups.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.G1\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G1\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G1</a> = Projective&lt;&lt;P as BnConfig&gt;::G1Config&gt;</h4></section></summary><div class='docblock'>An element in G1.</div></details><section id=\"associatedtype.G1Affine\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G1Affine\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G1Affine</a> = Affine&lt;&lt;P as BnConfig&gt;::G1Config&gt;</h4></section><details class=\"toggle\" open><summary><section id=\"associatedtype.G1Prepared\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G1Prepared\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G1Prepared</a> = G1Prepared&lt;P&gt;</h4></section></summary><div class='docblock'>A G1 element that has been preprocessed for use in a pairing.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.G2\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G2\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G2</a> = Projective&lt;&lt;P as BnConfig&gt;::G2Config&gt;</h4></section></summary><div class='docblock'>An element of G2.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.G2Affine\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G2Affine\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G2Affine</a> = Affine&lt;&lt;P as BnConfig&gt;::G2Config&gt;</h4></section></summary><div class='docblock'>The affine representation of an element in G2.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.G2Prepared\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.G2Prepared\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">G2Prepared</a> = G2Prepared&lt;P&gt;</h4></section></summary><div class='docblock'>A G2 element that has been preprocessed for use in a pairing.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.TargetField\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.TargetField\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">TargetField</a> = QuadExtField&lt;Fp12ConfigWrapper&lt;&lt;P as BnConfig&gt;::Fp12Config&gt;&gt;</h4></section></summary><div class='docblock'>The extension field that hosts the target group of the pairing.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.multi_miller_loop\" class=\"method trait-impl\"><a href=\"#method.multi_miller_loop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">multi_miller_loop</a>(\n    a: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Bn&lt;P&gt; as Pairing&gt;::G1Prepared&gt;&gt;,\n    b: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Bn&lt;P&gt; as Pairing&gt;::G2Prepared&gt;&gt;\n) -&gt; MillerLoopOutput&lt;Bn&lt;P&gt;&gt;</h4></section></summary><div class='docblock'>Computes the product of Miller loops for some number of (G1, G2) pairs.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.final_exponentiation\" class=\"method trait-impl\"><a href=\"#method.final_exponentiation\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">final_exponentiation</a>(\n    f: MillerLoopOutput&lt;Bn&lt;P&gt;&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.1/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;PairingOutput&lt;Bn&lt;P&gt;&gt;&gt;</h4></section></summary><div class='docblock'>Performs final exponentiation of the result of a <code>Self::multi_miller_loop</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.miller_loop\" class=\"method trait-impl\"><a href=\"#method.miller_loop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">miller_loop</a>(\n    a: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G1Prepared&gt;,\n    b: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G2Prepared&gt;\n) -&gt; MillerLoopOutput&lt;Self&gt;</h4></section></summary><div class='docblock'>Computes the Miller loop over <code>a</code> and <code>b</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.multi_pairing\" class=\"method trait-impl\"><a href=\"#method.multi_pairing\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">multi_pairing</a>(\n    a: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G1Prepared&gt;&gt;,\n    b: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G2Prepared&gt;&gt;\n) -&gt; PairingOutput&lt;Self&gt;</h4></section></summary><div class='docblock'>Computes a “product” of pairings.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.pairing\" class=\"method trait-impl\"><a href=\"#method.pairing\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">pairing</a>(\n    p: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G1Prepared&gt;,\n    q: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;Self::G2Prepared&gt;\n) -&gt; PairingOutput&lt;Self&gt;</h4></section></summary><div class='docblock'>Performs multiple pairing operations</div></details></div></details>","Pairing","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Debug-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, __f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.1/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.1/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.77.1/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","fastcrypto_zkp::bn254::zk_login_api::Bn254"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-Bn%3CP%3E\" class=\"impl\"><a href=\"#impl-Hash-for-Bn%3CP%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for Bn&lt;P&gt;<div class=\"where\">where\n    P: BnConfig,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;__HP&gt;(&amp;self, __state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;mut __HP</a>)<div class=\"where\">where\n    __HP: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,</div></h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.1/src/core/hash/mod.rs.html#238-240\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.slice.html\">[Self]</a>, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.1/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/1.77.1/core/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","fastcrypto_zkp::bn254::zk_login_api::Bn254"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()