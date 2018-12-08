using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.eac;

using System;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using NISTNamedCurves = org.bouncycastle.asn1.nist.NISTNamedCurves;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using DSASigner = org.bouncycastle.crypto.signers.DSASigner;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECPrivateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec;
	using ECPublicKeySpec = org.bouncycastle.jce.spec.ECPublicKeySpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using FixedSecureRandom = org.bouncycastle.util.test.FixedSecureRandom;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestRandomBigInteger = org.bouncycastle.util.test.TestRandomBigInteger;
	using TestRandomData = org.bouncycastle.util.test.TestRandomData;

	public class DSATest : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public DSATest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			random = new FixedSecureRandom(new byte[][] {k1, k2});
		}

		internal byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
		internal byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

		internal SecureRandom random;

		// DSA modified signatures, courtesy of the Google security team
		internal static readonly DSAPrivateKeySpec PRIVATE_KEY = new DSAPrivateKeySpec(new BigInteger("15382583218386677486843706921635237927801862255437148328980464126979"), new BigInteger("181118486631420055711787706248812146965913392568235070235446058914" + "1170708161715231951918020125044061516370042605439640379530343556" + "4101919053459832890139496933938670005799610981765220283775567361" + "4836626483403394052203488713085936276470766894079318754834062443" + "1033792580942743268186462355159813630244169054658542719322425431" + "4088256212718983105131138772434658820375111735710449331518776858" + "7867938758654181244292694091187568128410190746310049564097068770" + "8161261634790060655580211122402292101772553741704724263582994973" + "9109274666495826205002104010355456981211025738812433088757102520" + "562459649777989718122219159982614304359"), new BigInteger("19689526866605154788513693571065914024068069442724893395618704484701"), new BigInteger("2859278237642201956931085611015389087970918161297522023542900348" + "0877180630984239764282523693409675060100542360520959501692726128" + "3149190229583566074777557293475747419473934711587072321756053067" + "2532404847508798651915566434553729839971841903983916294692452760" + "2490198571084091890169933809199002313226100830607842692992570749" + "0504363602970812128803790973955960534785317485341020833424202774" + "0275688698461842637641566056165699733710043802697192696426360843" + "1736206792141319514001488556117408586108219135730880594044593648" + "9237302749293603778933701187571075920849848690861126195402696457" + "4111219599568903257472567764789616958430"));

		internal static readonly DSAPublicKeySpec PUBLIC_KEY = new DSAPublicKeySpec(new BigInteger("3846308446317351758462473207111709291533523711306097971550086650" + "2577333637930103311673872185522385807498738696446063139653693222" + "3528823234976869516765207838304932337200968476150071617737755913" + "3181601169463467065599372409821150709457431511200322947508290005" + "1780020974429072640276810306302799924668893998032630777409440831" + "4314588994475223696460940116068336991199969153649625334724122468" + "7497038281983541563359385775312520539189474547346202842754393945" + "8755803223951078082197762886933401284142487322057236814878262166" + "5072306622943221607031324846468109901964841479558565694763440972" + "5447389416166053148132419345627682740529"), PRIVATE_KEY.getP(), PRIVATE_KEY.getQ(), PRIVATE_KEY.getG());

		// The following test vectors check for signature malleability and bugs. That means the test
		// vectors are derived from a valid signature by modifying the ASN encoding. A correct
		// implementation of DSA should only accept correct DER encoding and properly handle the others.
		// Allowing alternative BER encodings is in many cases benign. An example where this kind of
		// signature malleability was a problem: https://en.bitcoin.it/wiki/Transaction_Malleability
		internal static readonly string[] MODIFIED_SIGNATURES = new string[] {"303e02811c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e" + "f41dd424a4e1c8f16967cf3365813fe8786236", "303f0282001c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f" + "9ef41dd424a4e1c8f16967cf3365813fe8786236", "303e021d001e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e" + "f41dd424a4e1c8f16967cf3365813fe8786236", "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd02811d00ade65988d237d30f9e" + "f41dd424a4e1c8f16967cf3365813fe8786236", "303f021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd0282001d00ade65988d237d30f" + "9ef41dd424a4e1c8f16967cf3365813fe8786236", "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021e0000ade65988d237d30f9e" + "f41dd424a4e1c8f16967cf3365813fe8786236", "30813d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e" + "f41dd424a4e1c8f16967cf3365813fe8786236", "3082003d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f" + "9ef41dd424a4e1c8f16967cf3365813fe8786236", "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9ef4" + "1dd424a4e1c8f16967cf3365813fe87862360000", "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100", "303e021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca802811d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3"};

		private void testModified()
		{
			KeyFactory kFact = KeyFactory.getInstance("DSA", "BC");
			PublicKey pubKey = kFact.generatePublic(PUBLIC_KEY);
			Signature sig = Signature.getInstance("DSA", "BC");

			for (int i = 0; i != MODIFIED_SIGNATURES.Length; i++)
			{
				sig.initVerify(pubKey);

				sig.update(Strings.toByteArray("Hello"));

				bool failed;

				try
				{
					failed = !sig.verify(Hex.decode(MODIFIED_SIGNATURES[i]));
				}
				catch (SignatureException)
				{
					failed = true;
				}

				isTrue("sig verified when shouldn't", failed);
			}
		}

		private void testCompat()
		{
			if (Security.getProvider("SUN") == null)
			{
				return;
			}

			Signature s = Signature.getInstance("DSA", "SUN");
			KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "SUN");
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

			g.initialize(512, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			PrivateKey sKey = p.getPrivate();
			PublicKey vKey = p.getPublic();

			//
			// sign SUN - verify with BC 
			//
			s.initSign(sKey);

			s.update(data);

			byte[] sigBytes = s.sign();

			s = Signature.getInstance("DSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("SUN -> BC verification failed");
			}

			//
			// sign BC - verify with SUN
			//

			s.initSign(sKey);

			s.update(data);

			sigBytes = s.sign();

			s = Signature.getInstance("DSA", "SUN");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("BC -> SUN verification failed");
			}

			//
			// key encoding test - BC decoding Sun keys
			//
			KeyFactory f = KeyFactory.getInstance("DSA", "BC");
			X509EncodedKeySpec x509s = new X509EncodedKeySpec(vKey.getEncoded());

			DSAPublicKey k1 = (DSAPublicKey)f.generatePublic(x509s);

			checkPublic(k1, vKey);

			PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());

			DSAPrivateKey k2 = (DSAPrivateKey)f.generatePrivate(pkcs8);

			checkPrivateKey(k2, sKey);

			//
			// key decoding test - SUN decoding BC keys
			// 
			f = KeyFactory.getInstance("DSA", "SUN");
			x509s = new X509EncodedKeySpec(k1.getEncoded());

			vKey = (DSAPublicKey)f.generatePublic(x509s);

			checkPublic(k1, vKey);

			pkcs8 = new PKCS8EncodedKeySpec(k2.getEncoded());
			sKey = f.generatePrivate(pkcs8);

			checkPrivateKey(k2, sKey);
		}

		private void testNullParameters()
		{
			KeyFactory f = KeyFactory.getInstance("DSA", "BC");
			X509EncodedKeySpec x509s = new X509EncodedKeySpec((new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa), new ASN1Integer(10001))).getEncoded());

			DSAPublicKey key1 = (DSAPublicKey)f.generatePublic(x509s);
			DSAPublicKey key2 = (DSAPublicKey)f.generatePublic(x509s);

			isTrue("parameters not absent", key1.getParams() == null && key2.getParams() == null);
			isTrue("hashCode mismatch", key1.GetHashCode() == key2.GetHashCode());
			isTrue("not equal", key1.Equals(key2));
			isTrue("encoding mismatch", Arrays.areEqual(x509s.getEncoded(), key1.getEncoded()));
		}

		private void testValidate()
		{
			DSAParameterSpec dsaParams = new DSAParameterSpec(new BigInteger("F56C2A7D366E3EBDEAA1891FD2A0D099" + "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" + "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" + "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" + "5909132627F51A0C866877E672E555342BDF9355347DBD43" + "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" + "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" + "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" + "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" + "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" + "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16), new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16), new BigInteger("8DC6CC814CAE4A1C05A3E186A6FE27EA" + "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" + "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" + "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" + "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" + "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" + "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" + "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" + "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" + "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" + "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)
		   );

			KeyFactory f = KeyFactory.getInstance("DSA", "BC");

			try
			{
				f.generatePublic(new DSAPublicKeySpec(BigInteger.valueOf(1), dsaParams.getP(), dsaParams.getG(), dsaParams.getQ()));

				fail("no exception");
			}
			catch (Exception e)
			{
				isTrue("mismatch", "invalid KeySpec: y value does not appear to be in correct group".Equals(e.Message));
			}
		}

		private void testNONEwithDSA()
		{
			byte[] dummySha1 = Hex.decode("01020304050607080910111213141516");

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");

			kpGen.initialize(512);

			KeyPair kp = kpGen.generateKeyPair();

			Signature sig = Signature.getInstance("NONEwithDSA", "BC");

			sig.initSign(kp.getPrivate());

			sig.update(dummySha1);

			byte[] sigBytes = sig.sign();

			sig.initVerify(kp.getPublic());

			sig.update(dummySha1);

			sig.verify(sigBytes);

			// reset test

			sig.update(dummySha1);

			if (!sig.verify(sigBytes))
			{
				fail("NONEwithDSA failed to reset");
			}

			// lightweight test
			DSAPublicKey key = (DSAPublicKey)kp.getPublic();
			DSAParameters @params = new DSAParameters(key.getParams().getP(), key.getParams().getQ(), key.getParams().getG());
			DSAPublicKeyParameters keyParams = new DSAPublicKeyParameters(key.getY(), @params);
			DSASigner signer = new DSASigner();
			ASN1Sequence derSig = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(sigBytes));

			signer.init(false, keyParams);

			if (!signer.verifySignature(dummySha1, ASN1Integer.getInstance(derSig.getObjectAt(0)).getValue(), ASN1Integer.getInstance(derSig.getObjectAt(1)).getValue()))
			{
				fail("NONEwithDSA not really NONE!");
			}
		}

		private void checkPublic(DSAPublicKey k1, PublicKey vKey)
		{
			if (!k1.getY().Equals(((DSAPublicKey)vKey).getY()))
			{
				fail("public number not decoded properly");
			}

			if (!k1.getParams().getG().Equals(((DSAPublicKey)vKey).getParams().getG()))
			{
				fail("public generator not decoded properly");
			}

			if (!k1.getParams().getP().Equals(((DSAPublicKey)vKey).getParams().getP()))
			{
				fail("public p value not decoded properly");
			}

			if (!k1.getParams().getQ().Equals(((DSAPublicKey)vKey).getParams().getQ()))
			{
				fail("public q value not decoded properly");
			}
		}

		private void checkPrivateKey(DSAPrivateKey k2, PrivateKey sKey)
		{
			if (!k2.getX().Equals(((DSAPrivateKey)sKey).getX()))
			{
				fail("private number not decoded properly");
			}

			if (!k2.getParams().getG().Equals(((DSAPrivateKey)sKey).getParams().getG()))
			{
				fail("private generator not decoded properly");
			}

			if (!k2.getParams().getP().Equals(((DSAPrivateKey)sKey).getParams().getP()))
			{
				fail("private p value not decoded properly");
			}

			if (!k2.getParams().getQ().Equals(((DSAPrivateKey)sKey).getParams().getQ()))
			{
				fail("private q value not decoded properly");
			}
		}

		private object serializeDeserialize(object o)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream oOut = new ObjectOutputStream(bOut);

			oOut.writeObject(o);
			oOut.close();

			ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

			return oIn.readObject();
		}

		/// <summary>
		/// X9.62 - 1998,<br>
		/// J.3.2, Page 155, ECDSA over the field Fp<br>
		/// an example with 239 bit prime
		/// </summary>
		private void testECDSA239bitPrime()
		{
			BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
			BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

			SecureRandom k = new TestRandomBigInteger(kData);

			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), spec);

			ECPublicKeySpec pubKey = new ECPublicKeySpec(curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), spec);

			Signature sgr = Signature.getInstance("ECDSA", "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKey);
			PublicKey vKey = f.generatePublic(pubKey);

			sgr.initSign(sKey, k);

			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("239 Bit EC verification failed");
			}

			BigInteger[] sig = derDecode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0]);
			}

			if (!s.Equals(sig[1]))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1]);
			}
		}

		private void testNONEwithECDSA239bitPrime()
		{
			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), spec);

			ECPublicKeySpec pubKey = new ECPublicKeySpec(curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), spec);

			Signature sgr = Signature.getInstance("NONEwithECDSA", "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKey);
			PublicKey vKey = f.generatePublic(pubKey);

			byte[] message = "abc".GetBytes();
			byte[] sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e64cb19604be06c57e761b3de5518f71de0f6e0cd2df677cec8a6ffcb690d");

			checkMessage(sgr, sKey, vKey, message, sig);

			message = "abcdefghijklmnopqrstuvwxyz".GetBytes();
			sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e43fd65b3363d76aabef8630572257dbb67c82818ad9fad31256539b1b02c");

			checkMessage(sgr, sKey, vKey, message, sig);

			message = "a very very long message gauranteed to cause an overflow".GetBytes();
			sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e7d5be84b22937a1691859a3c6fe45ed30b108574431d01b34025825ec17a");

			checkMessage(sgr, sKey, vKey, message, sig);
		}

		private void testECDSAP256sha3(ASN1ObjectIdentifier sigOid, int size, BigInteger s)
		{
			X9ECParameters p = NISTNamedCurves.getByName("P-256");
			KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");

			ECDomainParameters @params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());

			ECCurve curve = p.getCurve();

			ECParameterSpec spec = new ECParameterSpec(curve, p.getG(), p.getN()); // n

			ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), spec);

			ECPublicKeySpec pubKey = new ECPublicKeySpec(@params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), spec);

			doEcDsaTest("SHA3-" + size + "withECDSA", s, ecKeyFact, pubKey, priKey);
			doEcDsaTest(sigOid.getId(), s, ecKeyFact, pubKey, priKey);
		}

		private void doEcDsaTest(string sigName, BigInteger s, KeyFactory ecKeyFact, ECPublicKeySpec pubKey, ECPrivateKeySpec priKey)
		{
			SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));

			byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

			Signature dsa = Signature.getInstance(sigName, "BC");

			dsa.initSign(ecKeyFact.generatePrivate(priKey), k);

			dsa.update(M, 0, M.Length);

			byte[] encSig = dsa.sign();

			ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

			BigInteger r = new BigInteger("97354732615802252173078420023658453040116611318111190383344590814578738210384");

			BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
			if (!r.Equals(sigR))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r.ToString(16) + Strings.lineSeparator() + " got      : " + sigR.ToString(16));
			}

			BigInteger sigS = ASN1Integer.getInstance(sig.getObjectAt(1)).getValue();
			if (!s.Equals(sigS))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s.ToString(16) + Strings.lineSeparator() + " got      : " + sigS.ToString(16));
			}

			// Verify the signature
			dsa.initVerify(ecKeyFact.generatePublic(pubKey));

			dsa.update(M, 0, M.Length);

			if (!dsa.verify(encSig))
			{
				fail("signature fails");
			}
		}

		private void testDSAsha3(ASN1ObjectIdentifier sigOid, int size, BigInteger s)
		{
			DSAParameterSpec dsaParams = new DSAParameterSpec(new BigInteger("F56C2A7D366E3EBDEAA1891FD2A0D099" + "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" + "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" + "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" + "5909132627F51A0C866877E672E555342BDF9355347DBD43" + "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" + "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" + "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" + "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" + "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" + "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16), new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16), new BigInteger("8DC6CC814CAE4A1C05A3E186A6FE27EA" + "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" + "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" + "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" + "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" + "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" + "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" + "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" + "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" + "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" + "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)
		   );

			BigInteger x = new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16);

			BigInteger y = new BigInteger("2828003D7C747199143C370FDD07A286" + "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" + "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" + "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" + "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" + "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" + "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" + "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" + "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" + "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" + "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16);

			DSAPrivateKeySpec priKey = new DSAPrivateKeySpec(x, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

			DSAPublicKeySpec pubKey = new DSAPublicKeySpec(y, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

			KeyFactory dsaKeyFact = KeyFactory.getInstance("DSA", "BC");

			doDsaTest("SHA3-" + size + "withDSA", s, dsaKeyFact, pubKey, priKey);
			doDsaTest(sigOid.getId(), s, dsaKeyFact, pubKey, priKey);
		}

		private void doDsaTest(string sigName, BigInteger s, KeyFactory ecKeyFact, DSAPublicKeySpec pubKey, DSAPrivateKeySpec priKey)
		{
			SecureRandom k = new FixedSecureRandom(new FixedSecureRandom.Source[]
			{
				new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335"))),
				new FixedSecureRandom.Data(Hex.decode("01020304"))
			});

			byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

			Signature dsa = Signature.getInstance(sigName, "BC");

			dsa.initSign(ecKeyFact.generatePrivate(priKey), k);

			dsa.update(M, 0, M.Length);

			byte[] encSig = dsa.sign();

			ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

			BigInteger r = new BigInteger("4864074fe30e6601268ee663440e4d9b703f62673419864e91e9edb0338ce510", 16);

			BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
			if (!r.Equals(sigR))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r.ToString(16) + Strings.lineSeparator() + " got      : " + sigR.ToString(16));
			}

			BigInteger sigS = ASN1Integer.getInstance(sig.getObjectAt(1)).getValue();
			if (!s.Equals(sigS))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s.ToString(16) + Strings.lineSeparator() + " got      : " + sigS.ToString(16));
			}

			// Verify the signature
			dsa.initVerify(ecKeyFact.generatePublic(pubKey));

			dsa.update(M, 0, M.Length);

			if (!dsa.verify(encSig))
			{
				fail("signature fails");
			}
		}

		private void checkMessage(Signature sgr, PrivateKey sKey, PublicKey vKey, byte[] message, byte[] sig)
		{
			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

			SecureRandom k = new TestRandomBigInteger(kData);

			sgr.initSign(sKey, k);

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			if (!Arrays.areEqual(sigBytes, sig))
			{
				fail(StringHelper.NewString(message) + " signature incorrect");
			}

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail(StringHelper.NewString(message) + " verification failed");
			}
		}

		/// <summary>
		/// X9.62 - 1998,<br>
		/// J.2.1, Page 100, ECDSA over the field F2m<br>
		/// an example with 191 bit binary field
		/// </summary>
		private void testECDSA239bitBinary()
		{
			BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
			BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");

			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

			SecureRandom k = new TestRandomBigInteger(kData);

			X9ECParameters x9 = ECNamedCurveTable.getByName("c2tnb239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec @params = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), @params);

			ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), @params);

			Signature sgr = Signature.getInstance("ECDSA", "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKeySpec);
			PublicKey vKey = f.generatePublic(pubKeySpec);
			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.initSign(sKey, k);

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("239 Bit EC verification failed");
			}

			BigInteger[] sig = derDecode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0]);
			}

			if (!s.Equals(sig[1]))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1]);
			}
		}

		private void testECDSA239bitBinary(string algorithm, ASN1ObjectIdentifier oid)
		{
			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

			SecureRandom k = new TestRandomBigInteger(kData);

			X9ECParameters x9 = ECNamedCurveTable.getByName("c2tnb239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec @params = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), @params);

			ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), @params);

			Signature sgr = Signature.getInstance(algorithm, "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKeySpec);
			PublicKey vKey = f.generatePublic(pubKeySpec);
			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.initSign(sKey, k);

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr = Signature.getInstance(oid.getId(), "BC");

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("239 Bit EC RIPEMD160 verification failed");
			}
		}

		private void testGeneration()
		{
			Signature s = Signature.getInstance("DSA", "BC");
			KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};


			// test exception
			//
			try
			{
				g.initialize(513, new SecureRandom());

				fail("illegal parameter 513 check failed.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				g.initialize(510, new SecureRandom());

				fail("illegal parameter 510 check failed.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				g.initialize(1025, new SecureRandom());

				fail("illegal parameter 1025 check failed.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			g.initialize(512, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			PrivateKey sKey = p.getPrivate();
			PublicKey vKey = p.getPublic();

			s.initSign(sKey);

			s.update(data);

			byte[] sigBytes = s.sign();

			s = Signature.getInstance("DSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("DSA verification failed");
			}

			//
			// key decoding test - serialisation test
			//

			DSAPublicKey k1 = (DSAPublicKey)serializeDeserialize(vKey);

			checkPublic(k1, vKey);

			checkEquals(k1, vKey);

			DSAPrivateKey k2 = (DSAPrivateKey)serializeDeserialize(sKey);

			checkPrivateKey(k2, sKey);

			checkEquals(k2, sKey);

			if (!(k2 is PKCS12BagAttributeCarrier))
			{
				fail("private key not implementing PKCS12 attribute carrier");
			}

			//
			// ECDSA Fp generation test
			//
			s = Signature.getInstance("ECDSA", "BC");
			g = KeyPairGenerator.getInstance("ECDSA", "BC");

			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			g.initialize(ecSpec, new SecureRandom());

			p = g.generateKeyPair();

			sKey = p.getPrivate();
			vKey = p.getPublic();

			s.initSign(sKey);

			s.update(data);

			sigBytes = s.sign();

			s = Signature.getInstance("ECDSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("ECDSA verification failed");
			}

			//
			// key decoding test - serialisation test
			//

			PublicKey eck1 = (PublicKey)serializeDeserialize(vKey);

			checkEquals(eck1, vKey);

			PrivateKey eck2 = (PrivateKey)serializeDeserialize(sKey);

			checkEquals(eck2, sKey);

			// Named curve parameter
			g.initialize(new ECNamedCurveGenParameterSpec("P-256"), new SecureRandom());

			p = g.generateKeyPair();

			sKey = p.getPrivate();
			vKey = p.getPublic();

			s.initSign(sKey);

			s.update(data);

			sigBytes = s.sign();

			s = Signature.getInstance("ECDSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("ECDSA verification failed");
			}

			//
			// key decoding test - serialisation test
			//

			eck1 = (PublicKey)serializeDeserialize(vKey);

			checkEquals(eck1, vKey);

			eck2 = (PrivateKey)serializeDeserialize(sKey);

			checkEquals(eck2, sKey);

			//
			// ECDSA F2m generation test
			//
			s = Signature.getInstance("ECDSA", "BC");
			g = KeyPairGenerator.getInstance("ECDSA", "BC");

			x9 = ECNamedCurveTable.getByName("c2tnb239v1");
			curve = x9.getCurve();
			ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			g.initialize(ecSpec, new SecureRandom());

			p = g.generateKeyPair();

			sKey = p.getPrivate();
			vKey = p.getPublic();

			s.initSign(sKey);

			s.update(data);

			sigBytes = s.sign();

			s = Signature.getInstance("ECDSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("ECDSA verification failed");
			}

			//
			// key decoding test - serialisation test
			//

			eck1 = (PublicKey)serializeDeserialize(vKey);

			checkEquals(eck1, vKey);

			eck2 = (PrivateKey)serializeDeserialize(sKey);

			checkEquals(eck2, sKey);

			if (!(eck2 is PKCS12BagAttributeCarrier))
			{
				fail("private key not implementing PKCS12 attribute carrier");
			}
		}

		private void checkEquals(object o1, object o2)
		{
			if (!o1.Equals(o2))
			{
				fail("comparison test failed");
			}

			if (o1.GetHashCode() != o2.GetHashCode())
			{
				fail("hashCode test failed");
			}
		}

		private void testParameters()
		{
			AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DSA", "BC");
			a.init(512, random);
			AlgorithmParameters @params = a.generateParameters();

			byte[] encodeParams = @params.getEncoded();

			AlgorithmParameters a2 = AlgorithmParameters.getInstance("DSA", "BC");
			a2.init(encodeParams);

			// a and a2 should be equivalent!
			byte[] encodeParams_2 = a2.getEncoded();

			if (!areEqual(encodeParams, encodeParams_2))
			{
				fail("encode/decode parameters failed");
			}

			DSAParameterSpec dsaP = (DSAParameterSpec)@params.getParameterSpec(typeof(DSAParameterSpec));

			KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
			g.initialize(dsaP, new SecureRandom());
			KeyPair p = g.generateKeyPair();

			PrivateKey sKey = p.getPrivate();
			PublicKey vKey = p.getPublic();

			Signature s = Signature.getInstance("DSA", "BC");
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

			s.initSign(sKey);

			s.update(data);

			byte[] sigBytes = s.sign();

			s = Signature.getInstance("DSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("DSA verification failed");
			}
		}

		private void testDSA2Parameters()
		{
			byte[] seed = Hex.decode("4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0");

			AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DSA", "BC");
			a.init(2048, new DSATestSecureRandom(this, seed));
			AlgorithmParameters @params = a.generateParameters();

			DSAParameterSpec dsaP = (DSAParameterSpec)@params.getParameterSpec(typeof(DSAParameterSpec));

			if (!dsaP.getQ().Equals(new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16)))
			{
				fail("Q incorrect");
			}

			if (!dsaP.getP().Equals(new BigInteger("F56C2A7D366E3EBDEAA1891FD2A0D099" + "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" + "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" + "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" + "5909132627F51A0C866877E672E555342BDF9355347DBD43" + "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" + "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" + "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" + "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" + "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" + "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16)))
			{
				fail("P incorrect");
			}

			if (!dsaP.getG().Equals(new BigInteger("8DC6CC814CAE4A1C05A3E186A6FE27EA" + "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" + "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" + "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" + "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" + "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" + "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" + "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" + "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" + "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" + "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)))
			{
				fail("G incorrect");
			}

			KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
			g.initialize(dsaP, new TestRandomBigInteger(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C")));
			KeyPair p = g.generateKeyPair();

			DSAPrivateKey sKey = (DSAPrivateKey)p.getPrivate();
			DSAPublicKey vKey = (DSAPublicKey)p.getPublic();

			if (!vKey.getY().Equals(new BigInteger("2828003D7C747199143C370FDD07A286" + "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" + "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" + "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" + "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" + "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" + "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" + "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" + "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" + "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" + "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16)))
			{
				fail("Y value incorrect");
			}

			if (!sKey.getX().Equals(new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16)))
			{
				fail("X value incorrect");
			}

			byte[] encodeParams = @params.getEncoded();

			AlgorithmParameters a2 = AlgorithmParameters.getInstance("DSA", "BC");
			a2.init(encodeParams);

			// a and a2 should be equivalent!
			byte[] encodeParams_2 = a2.getEncoded();

			if (!areEqual(encodeParams, encodeParams_2))
			{
				fail("encode/decode parameters failed");
			}

			Signature s = Signature.getInstance("DSA", "BC");
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

			s.initSign(sKey);

			s.update(data);

			byte[] sigBytes = s.sign();

			s = Signature.getInstance("DSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("DSA verification failed");
			}
		}

		private void testKeyGeneration(int keysize)
		{
			KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "BC");
			generator.initialize(keysize);
			KeyPair keyPair = generator.generateKeyPair();
			DSAPrivateKey priv = (DSAPrivateKey)keyPair.getPrivate();
			DSAParams @params = priv.getParams();
			isTrue("keysize mismatch", keysize == @params.getP().bitLength());
			// The NIST standard does not fully specify the size of q that
			// must be used for a given key size. Hence there are differences.
			// For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
			// but the SUN provider uses 224 bits. Both are acceptable sizes.
			// The tests below simply asserts that the size of q does not decrease the
			// overall security of the DSA.
			int qsize = @params.getQ().bitLength();
			switch (keysize)
			{
			case 1024:
				isTrue("Invalid qsize for 1024 bit key:" + qsize, qsize >= 160);
				break;
			case 2048:
				isTrue("Invalid qsize for 2048 bit key:" + qsize, qsize >= 224);
				break;
			case 3072:
				isTrue("Invalid qsize for 3072 bit key:" + qsize, qsize >= 256);
				break;
			default:
				fail("Invalid key size:" + keysize);
			break;
			}
			// Check the length of the private key.
			// For example GPG4Browsers or the KJUR library derived from it use
			// q.bitCount() instead of q.bitLength() to determine the size of the private key
			// and hence would generate keys that are much too small.
			isTrue("privkey error", priv.getX().bitLength() >= qsize - 32);
		}

		private void testKeyGenerationAll()
		{
			testKeyGeneration(1024);
			testKeyGeneration(2048);
			testKeyGeneration(3072);
		}

		public override void performTest()
		{
			testCompat();
			testNONEwithDSA();

			testDSAsha3(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, 224, new BigInteger("613202af2a7f77e02b11b5c3a5311cf6b412192bc0032aac3ec127faebfc6bd0", 16));
			testDSAsha3(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, 256, new BigInteger("2450755c5e15a691b121bc833b97864e34a61ee025ecec89289c949c1858091e", 16));
			testDSAsha3(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, 384, new BigInteger("7aad97c0b71bb1e1a6483b6948a03bbe952e4780b0cee699a11731f90d84ddd1", 16));
			testDSAsha3(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, 512, new BigInteger("725ad64d923c668e64e7c3898b5efde484cab49ce7f98c2885d2a13a9e355ad4", 16));

			testECDSA239bitPrime();
			testNONEwithECDSA239bitPrime();
			testECDSA239bitBinary();
			testECDSA239bitBinary("RIPEMD160withECDSA", TeleTrusTObjectIdentifiers_Fields.ecSignWithRipemd160);
			testECDSA239bitBinary("SHA1withECDSA", TeleTrusTObjectIdentifiers_Fields.ecSignWithSha1);
			testECDSA239bitBinary("SHA224withECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			testECDSA239bitBinary("SHA256withECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			testECDSA239bitBinary("SHA384withECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			testECDSA239bitBinary("SHA512withECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			testECDSA239bitBinary("SHA1withCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1);
			testECDSA239bitBinary("SHA224withCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224);
			testECDSA239bitBinary("SHA256withCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256);
			testECDSA239bitBinary("SHA384withCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384);
			testECDSA239bitBinary("SHA512withCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512);

			testECDSAP256sha3(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, 224, new BigInteger("84d7d8e68e405064109cd9fc3e3026d74d278aada14ce6b7a9dd0380c154dc94", 16));
			testECDSAP256sha3(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, 256, new BigInteger("99a43bdab4af989aaf2899079375642f2bae2dce05bcd8b72ec8c4a8d9a143f", 16));
			testECDSAP256sha3(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, 384, new BigInteger("aa27726509c37aaf601de6f7e01e11c19add99530c9848381c23365dc505b11a", 16));
			testECDSAP256sha3(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, 512, new BigInteger("f8306b57a1f5068bf12e53aabaae39e2658db39bc56747eaefb479995130ad16", 16));

			testGeneration();
			testParameters();
			testDSA2Parameters();
			testNullParameters();
			testValidate();
			testModified();
			testKeyGenerationAll();
		}

		public virtual BigInteger[] derDecode(byte[] encoding)
		{
			ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
			ASN1InputStream aIn = new ASN1InputStream(bIn);
			ASN1Sequence s = (ASN1Sequence)aIn.readObject();

			BigInteger[] sig = new BigInteger[2];

			sig[0] = ((ASN1Integer)s.getObjectAt(0)).getValue();
			sig[1] = ((ASN1Integer)s.getObjectAt(1)).getValue();

			return sig;
		}

		public override string getName()
		{
			return "DSA/ECDSA";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new DSATest());
		}

		public class DSATestSecureRandom : TestRandomData
		{
			private readonly DSATest outerInstance;

			internal bool first = true;

			public DSATestSecureRandom(DSATest outerInstance, byte[] value) : base(value)
			{
				this.outerInstance = outerInstance;
			}

		   public override void nextBytes(byte[] bytes)
		   {
			   if (first)
			   {
				   base.nextBytes(bytes);
				   first = false;
			   }
			   else
			   {
				   bytes[bytes.Length - 1] = 2;
			   }
		   }
		}
	}

}