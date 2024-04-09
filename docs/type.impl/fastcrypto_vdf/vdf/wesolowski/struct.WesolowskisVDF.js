(function() {var type_impls = {
"fastcrypto_vdf":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-WesolowskisVDF%3CG,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_vdf/vdf/wesolowski/mod.rs.html#30-42\">source</a><a href=\"#impl-WesolowskisVDF%3CG,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"fastcrypto_vdf/trait.ParameterizedGroupElement.html\" title=\"trait fastcrypto_vdf::ParameterizedGroupElement\">ParameterizedGroupElement</a> + <a class=\"trait\" href=\"fastcrypto_vdf/trait.UnknownOrderGroupElement.html\" title=\"trait fastcrypto_vdf::UnknownOrderGroupElement\">UnknownOrderGroupElement</a>, F: <a class=\"trait\" href=\"fastcrypto_vdf/vdf/wesolowski/fiat_shamir/trait.FiatShamir.html\" title=\"trait fastcrypto_vdf::vdf::wesolowski::fiat_shamir::FiatShamir\">FiatShamir</a>&lt;G&gt;&gt; <a class=\"struct\" href=\"fastcrypto_vdf/vdf/wesolowski/struct.WesolowskisVDF.html\" title=\"struct fastcrypto_vdf::vdf::wesolowski::WesolowskisVDF\">WesolowskisVDF</a>&lt;G, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_vdf/vdf/wesolowski/mod.rs.html#35-41\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_vdf/vdf/wesolowski/struct.WesolowskisVDF.html#tymethod.new\" class=\"fn\">new</a>(group_parameter: G::<a class=\"associatedtype\" href=\"fastcrypto_vdf/trait.ParameterizedGroupElement.html#associatedtype.ParameterType\" title=\"type fastcrypto_vdf::ParameterizedGroupElement::ParameterType\">ParameterType</a>, iterations: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.u64.html\">u64</a>) -&gt; Self</h4></section></summary><div class=\"docblock\"><p>Create a new VDF using the group defined by the given group parameter. Evaluating this VDF\nwill require computing <code>2^iterations * input</code> which requires <code>iterations</code> group operations.</p>\n</div></details></div></details>",0,"fastcrypto_vdf::vdf::wesolowski::StrongVDF"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-VDF-for-WesolowskisVDF%3CG,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_vdf/vdf/wesolowski/mod.rs.html#44-94\">source</a><a href=\"#impl-VDF-for-WesolowskisVDF%3CG,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"fastcrypto_vdf/trait.ParameterizedGroupElement.html\" title=\"trait fastcrypto_vdf::ParameterizedGroupElement\">ParameterizedGroupElement</a>&lt;ScalarType = <a class=\"struct\" href=\"https://docs.rs/num-bigint/0.4/num_bigint/bigint/struct.BigInt.html\" title=\"struct num_bigint::bigint::BigInt\">BigInt</a>&gt; + <a class=\"trait\" href=\"fastcrypto_vdf/trait.UnknownOrderGroupElement.html\" title=\"trait fastcrypto_vdf::UnknownOrderGroupElement\">UnknownOrderGroupElement</a>, F: <a class=\"trait\" href=\"fastcrypto_vdf/vdf/wesolowski/fiat_shamir/trait.FiatShamir.html\" title=\"trait fastcrypto_vdf::vdf::wesolowski::fiat_shamir::FiatShamir\">FiatShamir</a>&lt;G&gt;&gt; <a class=\"trait\" href=\"fastcrypto_vdf/vdf/trait.VDF.html\" title=\"trait fastcrypto_vdf::vdf::VDF\">VDF</a> for <a class=\"struct\" href=\"fastcrypto_vdf/vdf/wesolowski/struct.WesolowskisVDF.html\" title=\"struct fastcrypto_vdf::vdf::wesolowski::WesolowskisVDF\">WesolowskisVDF</a>&lt;G, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.InputType\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.InputType\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_vdf/vdf/trait.VDF.html#associatedtype.InputType\" class=\"associatedtype\">InputType</a> = G</h4></section></summary><div class='docblock'>The type of the input to the VDF.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.OutputType\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.OutputType\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_vdf/vdf/trait.VDF.html#associatedtype.OutputType\" class=\"associatedtype\">OutputType</a> = G</h4></section></summary><div class='docblock'>The type of the output from the VDF.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.ProofType\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.ProofType\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_vdf/vdf/trait.VDF.html#associatedtype.ProofType\" class=\"associatedtype\">ProofType</a> = G</h4></section></summary><div class='docblock'>The type of the proof of correctness for this VDF.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.evaluate\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_vdf/vdf/wesolowski/mod.rs.html#53-76\">source</a><a href=\"#method.evaluate\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_vdf/vdf/trait.VDF.html#tymethod.evaluate\" class=\"fn\">evaluate</a>(&amp;self, input: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;G</a>) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.tuple.html\">(G, G)</a>&gt;</h4></section></summary><div class='docblock'>Evaluate this VDF and return the output and a proof of correctness.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.verify\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_vdf/vdf/wesolowski/mod.rs.html#78-93\">source</a><a href=\"#method.verify\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_vdf/vdf/trait.VDF.html#tymethod.verify\" class=\"fn\">verify</a>(&amp;self, input: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;G</a>, output: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;G</a>, proof: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.reference.html\">&amp;G</a>) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.1/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class='docblock'>Verify the output and proof from a VDF.</div></details></div></details>","VDF","fastcrypto_vdf::vdf::wesolowski::StrongVDF"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()